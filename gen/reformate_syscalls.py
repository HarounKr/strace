def reformat_file(input_file, output_file):
    try:
        with open(input_file, "r") as infile, open(output_file, "w") as outfile:
            line_number = 0
            for line in infile:
                line = line.strip()
                
                if not line:
                    continue

                if line.startswith("//"):
                    continue
                if line.endswith(","):
                    line = line[:-1]
                if "//" in line:
                    line = line.split("//")[0].strip()

                reformatted_line = f"{{{line_number}, {line}}},\n"
                outfile.write(reformatted_line)
                line_number += 1

        print(f"Fichier reformatté écrit dans : {output_file}")
    except FileNotFoundError:
        print(f"Le fichier '{input_file}' est introuvable.")
    except Exception as e:
        print(f"Erreur : {e}")

# Exemple d'utilisation
input_file = "syscalls32.txt"
output_file = "formatted_syscalls32.c"
reformat_file(input_file, output_file)
