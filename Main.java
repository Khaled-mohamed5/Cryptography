import java.util.Scanner;

public class Main {

    public static String stringToBinary(String s) {
        StringBuilder result = new StringBuilder();
        for (char c : s.toCharArray()) {
            result.append(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0'));
        }
        return result.toString();
    }

    public static String binaryToString(String binary) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 8) {
            String byteString = binary.substring(i, i + 8);
            int charCode = Integer.parseInt(byteString, 2);
            text.append((char) charCode);
        }
        return text.toString();
    }

    public static String runDES(String binaryText, DESKEY desKey, boolean isEncrypt) {

        PLAINTEXT pt = new PLAINTEXT(binaryText);
        String ipText = pt.Ip();

        String left = ipText.substring(0, 32);
        String right = ipText.substring(32);

        for (int round = 0; round < 16; round++) {
            String subkey = isEncrypt ? desKey.getSubkey(round) : desKey.getSubkey(15 - round);
            String fOut = DES.feistel(right, subkey);
            String newRight = DES.XOR(left, fOut);
            left = right;
            right = newRight;
        }


        String combined = right + left;
        PLAINTEXT finalBlock = new PLAINTEXT(combined);
        return finalBlock.IpInv();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter 8-byte plaintext: ");
        String plainText = scanner.nextLine();
        while (plainText.length() != 8) {
            System.out.print(" enter exactly 8 bytes: ");
            plainText = scanner.nextLine();
        }

        System.out.print("Enter 8-byte key: ");
        String key = scanner.nextLine();
        while (key.length() != 8) {
            System.out.print(" enter exactly 8 bytes: ");
            key = scanner.nextLine();
        }

        String binaryPlainText = stringToBinary(plainText);
        String binaryKey = stringToBinary(key);

        DESKEY desKey = new DESKEY(binaryKey);


        String encryptedBinary = runDES(binaryPlainText, desKey, true);
        String encryptedText = binaryToString(encryptedBinary);


        String decryptedBinary = runDES(encryptedBinary, desKey, false);
        String decryptedText = binaryToString(decryptedBinary);

        System.out.println("\n Encryption :");
        System.out.println("Encrypted binary: " + encryptedBinary);
        System.out.println("Encrypted text  : " + encryptedText);

        System.out.println("\n Decryption :");
        System.out.println("Decrypted binary: " + decryptedBinary);
        System.out.println("Decrypted text  : " + decryptedText);

        scanner.close();
    }
}
