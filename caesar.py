def encrypt(text, shift):
    """
    Encrypts the input text using Caesar Cipher.
    
    :param text: The string to be encrypted.
    :param shift: The number of positions to shift each character.
    :return: The encrypted string.
    """
    result = ""
    
    for char in text:
        # Encrypt uppercase letters
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        # Encrypt lowercase letters
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        # Leave non-alphabetic characters as is
        else:
            result += char
    
    return result


if __name__ == "__main__":
    # Input string and shift value
    text = input("Enter the text to encrypt: ")
    shift = int(input("Enter the shift value (e.g., 3): "))
    
    # Encrypt the text
    encrypted_text = encrypt(text, shift)
    print(f"Encrypted Text: {encrypted_text}")