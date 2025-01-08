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
        # Enlever les pointeurs pour mapper correctement
        base_token = token.replace('*', '').strip()
        if base_token in TYPE_MAPPING:
            # Remplacer le typedef
            replacement = TYPE_MAPPING[base_token]
            # Réattacher les pointeurs
            #pointer_part = token[len(base_token):]
            replaced_tokens.append(replacement)
        else:
            replaced_tokens.append(token)
    return " ".join(replaced_tokens)

def parse_syscalls_from_header(header_path):
    """Parse le fichier `unistd_*.h` pour extraire les noms des syscalls."""
    syscalls = []
    with open(header_path, "r") as f:
        for line in f:
            # Identifier les définitions de syscalls
            match = re.match(r"#define\s+__NR_(\w+)\s+\d+", line)
            if match:
                syscalls.append(match.group(1))  # Extraire le nom du syscall
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
    # Cherche un bloc commençant après SYNOPSIS et s'arrêtant avant la prochaine section en MAJ
    match = re.search(r'(?s)(?<=SYNOPSIS\n)(.*?)(?=\n[A-Z ]+\n)', man_page_text)
    if match:
        return match.group(1)
    return man_page_text  # fallback: si pas trouvé, on renvoie tout.

def parse_prototype_from_man(man_page, syscall_name):
    synopsis = extract_synopsis(man_page)
    if not synopsis:
        return None, None, None

    # Expression régulière plus flexible, multi-lignes
    pattern = rf'(?s)\b((?:[a-zA-Z_][\w\s\*\d]*))\b{syscall_name}\s*\(([^)]*)\)'
    match = re.search(pattern, synopsis)
    if not match:
        return None, None, None

    return_type_raw = match.group(1).strip()
    args_raw = match.group(2).strip()
    args_raw = args_raw.replace('const', '')

    # Nettoyer le type de retour : enlever les double-espaces etc..
    return_type = re.sub(r'\s+', ' ', return_type_raw).strip()
    return_type = replace_types(return_type)

    # Traiter les arguments
    if not args_raw or args_raw.lower() == 'void':
        arg_list = []
    else:
        # Séparer par virgules
        arg_list = [arg.strip() for arg in args_raw.split(',')]

    # Extraire uniquement le type des arguments
    arg_types = []
    for arg in arg_list:
        parts = arg.split()
        if len(parts) >= 2:
            arg_type_raw = " ".join(parts[:-1])
        else:
            arg_type_raw = parts[0]  # Cas où seul le type est présent
        arg_type = replace_types(arg_type_raw)
        arg_types.append(arg_type)

    return return_type, len(arg_types), arg_types

def format_syscall(syscall_name, return_type, num_args, arg_types):
    #Formate les informations dans la structure `t_syscall`.
    if arg_types:
        args_list = ", ".join([f'"{arg}"' for arg in arg_types])
    else:
        args_list = "NULL"
    if return_type:
        return_type_str = f'"{return_type}"'
    else:
        return_type_str = "NULL"
    return f'    {{"{syscall_name}", {num_args}, {{{args_list}}}, {return_type_str}}},'

def generate_syscalls(header_path, output_file):
    #Génère le fichier de syscalls à partir du header spécifié.
    print(f"Lecture des syscalls depuis {header_path}...")
    syscalls = parse_syscalls_from_header(header_path)
    print(f"{len(syscalls)} syscalls trouvés dans {header_path}.")
    not_found = []
    formatted_syscalls = []
    for syscall in syscalls:
        print(f"Traitement du syscall: {syscall}...")
        man_page = fetch_man_syscall(syscall)
        if not man_page:
            print(f"  Pas de page man trouvée pour {syscall}")
            continue

        return_type, num_args, arg_types = parse_prototype_from_man(man_page, syscall)
        if not return_type or num_args is None or arg_types is None:
            print(f"  Impossible d'extraire les détails pour {syscall}")
            not_found.append(syscall)
            continue

        formatted_syscalls.append(
            format_syscall(syscall, return_type, num_args, arg_types)
        )
    with open(output_file, "w") as f:
        f.write("t_syscall syscalls[] = {\n")
        f.write("\n".join(formatted_syscalls))
        f.write("\n    {NULL, 0, {NULL}, NULL}\n};\n")

    # Pour faire la recherche manuellement
    with open("not_found", "a") as f:
        f.write(f"Syscalls not found for {output_file} : {not_found} \n")

    print(f"Syscalls sauvegardés dans {output_file}")

def main():
    # Définitions des headers et fichiers de sortie
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