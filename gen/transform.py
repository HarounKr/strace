import re

def reformat_syscalls(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            # Identifier les lignes qui contiennent une définition syscall
            match = re.match(r"^\s*\{(\d+), \{(.+?)\}\},", line)
            if match:
                syscall_number = match.group(1)
                syscall_content = match.group(2)
                # Reformater la ligne dans le nouveau format
                formatted_line = f"    {{{syscall_number}, {syscall_content}}},\n"
                outfile.write(formatted_line)
            else:
                # Si ce n'est pas une ligne de syscall, la copier directement
                outfile.write(line)

# Entrées de fichier
input_file = "syscalls32.c"  # Remplacez par le chemin de votre fichier d'entrée
output_file = "syscalls_formatted.txt"  # Remplacez par le chemin de votre fichier de sortie

# Appeler la fonction pour reformater le fichier
reformat_syscalls(input_file, output_file)

print(f"Les syscalls ont été reformattés et enregistrés dans {output_file}.")
