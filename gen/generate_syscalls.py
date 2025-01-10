import os
import re
import subprocess

# Mapping des typedefs vers leurs types bruts
TYPE_MAPPING = {
    "size_t": "unsigned long",
    "ssize_t": "long",
    "pid_t": "int",
    "off_t": "long",
    "mode_t": "unsigned int",
    "uid_t": "unsigned int",
    "gid_t": "unsigned int",
    "socklen_t": "unsigned int",
    "caddr_t": "unsigned long",
    "fd_set": "addr",
    "clockid_t": "addr",
    "timer_t": "addr",
    "u64": "unsigned int",
    "nfds_t": "addr",
    "off64_t": "unsigned int",
    "sigset_t": "addr",
    "siginfo_t": "addr",
    "uint64_t": "unsigned long",
    "uint32_t": "unsigned int",
    "loff_t": "long long",
    "key_t": "addr",
    "sighandler_t": "addr",
    "kernel_sigset_t": "addr",
    "dev_t": "addr",
    "id_t": "unsigned int",
    "cap_user_header_t": "addr",
    "cpu_set_t": "int",
    "aio_context_t": "unsigned int",
    "struct": "addr"
}


def replace_types(arg_type):
    tokens = arg_type.split()
    replaced_tokens = []

    for token in tokens:
        star_part = ''
        while token.endswith('*'):
            star_part += '*'
            token = token[:-1]

        base_token = token.strip()

        if base_token in TYPE_MAPPING:
            replaced_token = TYPE_MAPPING[base_token] + star_part
        else:
            replaced_token = base_token + star_part

        replaced_tokens.append(replaced_token)

    return " ".join(replaced_tokens)


def parse_syscalls_from_header(header_path):
    """Parse le fichier `unistd_*.h` pour extraire les numéros et noms des syscalls."""
    syscalls = []
    with open(header_path, "r") as f:
        for line in f:
            match = re.match(r"#define\s+__NR_(\w+)\s+(\d+)", line)
            if match:
                name = match.group(1)
                number = int(match.group(2))
                syscalls.append((number, name))
    return syscalls


def fetch_man_syscall(syscall):
    man_name = syscall
    try:
        command = ["man", "2", man_name]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except Exception as e:
        print(f"Erreur lors de l'exécution de {' '.join(command)}: {e}")
    return None


def extract_synopsis(man_page_text):
    match = re.search(r'(?s)(?<=SYNOPSIS\n)(.*?)(?=\n[A-Z ]+\n)', man_page_text)
    if match:
        return match.group(1)
    return None


def parse_prototype_from_man(man_page, syscall_name):
    synopsis = extract_synopsis(man_page)
    if not synopsis:
        return None, None, None

    # On cherche le prototype du syscall, sous la forme:
    #  <type> syscall_name (<type arg1, ...>)
    pattern = rf'(?s)\b((?:[a-zA-Z_][\w\s\*\d]*))\b{syscall_name}\s*\(([^)]*)\)'
    match = re.search(pattern, synopsis)
    if not match:
        return None, None, None

    return_type_raw = match.group(1).strip()
    args_raw = match.group(2).strip()
    args_raw = args_raw.replace('const', '')

    return_type = re.sub(r'\s+', ' ', return_type_raw).strip()
    return_type = replace_types(return_type)

    if not args_raw or args_raw.lower() == 'void':
        arg_list = []
    else:
        arg_list = [arg.strip() for arg in args_raw.split(',')]

    arg_types = []
    for arg in arg_list:
        parts = arg.split()
        if len(parts) >= 2:
            arg_type_raw = " ".join(parts[:-1])
        else:
            arg_type_raw = parts[0]
        arg_type = replace_types(arg_type_raw)
        arg_types.append(arg_type)

    return return_type, len(arg_types), arg_types


def format_syscall(number, syscall_name, return_type, num_args, arg_types, not_found=False):
    """Formate les informations dans la structure {number, {"name", args_count, {"args"}, "return_type"}}."""
    if arg_types:
        args_list = ", ".join([f'"{arg}"' for arg in arg_types])
    else:
        args_list = "NULL"
    return_type_str = f'"{return_type}"' if return_type else "NULL"
    syscall_entry = f'    {{{number}, {{"{syscall_name}", {num_args}, {{{args_list}}}, {return_type_str}}}}}'
    if not_found:
        syscall_entry += " /* syscall pas trouvé */"
    return syscall_entry


def generate_syscalls(header_path, output_file):
    print(f"Lecture des syscalls depuis {header_path}...")
    syscalls = parse_syscalls_from_header(header_path)
    print(f"{len(syscalls)} syscalls trouvés dans {header_path}.")
    formatted_syscalls = []

    for number, syscall in syscalls:
        print(f"Traitement du syscall: {syscall} (numéro {number})...")
        man_page = fetch_man_syscall(syscall)
        if not man_page:
            print(f"  Pas de page man trouvée pour {syscall}")
            formatted_syscalls.append(
                format_syscall(number, syscall, "int", 0, [], not_found=True)  # Valeurs par défaut avec commentaire
            )
            continue

        return_type, num_args, arg_types = parse_prototype_from_man(man_page, syscall)
        if not return_type or num_args is None or arg_types is None:
            print(f"  Impossible d'extraire les détails pour {syscall}")
            formatted_syscalls.append(
                format_syscall(number, syscall, "int", 0, [], not_found=True)  # Valeurs par défaut avec commentaire
            )
            continue

        formatted_syscalls.append(
            format_syscall(number, syscall, return_type, num_args, arg_types)
        )

    with open(output_file, "w") as f:
        f.write("t_syscall syscalls[] = {\n")
        f.write(",\n".join(formatted_syscalls))
        f.write("\n    {0, {NULL, 0, {NULL}, NULL}}\n};\n")

    print(f"Syscalls sauvegardés dans {output_file}")


def main():
    headers = {
        "64": "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "32": "/usr/include/x86_64-linux-gnu/asm/unistd_32.h"
    }
    output_files = {
        "64": "syscalls64.c",
        "32": "syscalls32.c"
    }

    for arch in ["64", "32"]:
        header_path = headers[arch]
        output_file = output_files[arch]
        if not os.path.exists(header_path):
            print(f"Header pour l'architecture {arch} non trouvé: {header_path}")
            continue
        generate_syscalls(header_path, output_file)

if __name__ == "__main__":
    main()
