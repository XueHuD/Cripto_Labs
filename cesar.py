

import sys


def cifrar_cesar(texto, corrimiento):

    resultado = ""
    corrimiento = corrimiento % 26  # normaliza el desplazamiento

    for caracter in texto:
        if caracter.isupper():
            # 'A' = 65 en ASCII
            nuevo = (ord(caracter) - ord('A') + corrimiento) % 26 + ord('A')
            resultado += chr(nuevo)
        elif caracter.islower():
            # 'a' = 97 en ASCII
            nuevo = (ord(caracter) - ord('a') + corrimiento) % 26 + ord('a')
            resultado += chr(nuevo)
        else:
            # cualquier otro caracter se mantiene sin cambios
            resultado += caracter

    return resultado


def main():
    # Parametros por linea de comandos: argv[1] = texto, argv[2] = corrimiento
    if len(sys.argv) == 3:
        texto = sys.argv[1]
        try:
            corrimiento = int(sys.argv[2])
        except ValueError:
            print("El corrimiento debe ser un numero entero.")
            sys.exit(1)

    # Sin argumentos -> modo interactivo
    elif len(sys.argv) == 1:
        texto = input("Ingrese el texto a cifrar: ")
        while True:
            try:
                corrimiento = int(input("Ingrese el corrimiento (numero entero): "))
                break
            except ValueError:
                print("El corrimiento debe ser un numero entero. Intente de nuevo.")

    # Cantidad de argumentos incorrecta -> mostrar uso
    else:
        print('Uso: python3 cesar.py "texto a cifrar" <corrimiento>')
        sys.exit(1)

    # Imprime solo el texto cifrado
    print(cifrar_cesar(texto, corrimiento))


if __name__ == "__main__":
    main()
