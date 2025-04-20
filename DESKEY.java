public class DESKEY {

    private static final int[] PC1 = {
            57,49,41,33,25,17,9,1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,21,13,5,28,20,12,4
    };

    private static final int[] PC2 = {
            14,17,11,24,1,5,3,28,15,6,21,10,
            23,19,12,4,26,8,16,7,27,20,13,2,
            41,52,31,37,47,55,30,40,51,45,33,48,
            44,49,39,56,34,53,46,42,50,36,29,32
    };

    private static final int[] SHIFTS = {
            1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
    };

    private final String[] subkeys = new String[16];

    public DESKEY(String key64) {
        String key56 = permute(key64, PC1);
        String c = key56.substring(0, 28);
        String d = key56.substring(28);

        for (int i = 0; i < 16; i++) {
            c = leftShift(c, SHIFTS[i]);
            d = leftShift(d, SHIFTS[i]);
            String combined = c + d;
            subkeys[i] = permute(combined, PC2);
        }
    }

    private static String permute(String input, int[] table) {
        StringBuilder output = new StringBuilder();
        for (int index : table) {
            output.append(input.charAt(index - 1));
        }
        return output.toString();
    }

    private static String leftShift(String input, int shift) {
        return input.substring(shift) + input.substring(0, shift);
    }

    public void printSubkeys() {
        for (int i = 0; i < subkeys.length; i++) {
            System.out.println("Subkey " + (i + 1) + ": " + subkeys[i]);
        }
    }

    public String getSubkey(int i) {
        return subkeys[i];
    }
}
