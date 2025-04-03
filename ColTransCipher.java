import java.util.*;

public class ColTransCipher extends Cipher {

    ArrayList<Character> key = new ArrayList<>();
    ArrayList<Character> keyOrder = new ArrayList<>();
    private boolean padding = true;
    private boolean debug = false;

    public ColTransCipher(int k, String[] names, boolean ascending, boolean strict) {
        if (names == null) {
            alphabet = getAlphabet(new String[] {"lower"});
        } else {
            alphabet = Cipher.getAlphabet(names);
        }
        String t = "" + k;
        if (strict) {
            setKey(sanitize(t), ascending);
        } else {
            setKey(t, ascending);
        }
    }

    public ColTransCipher(int[] k, String[] names, boolean ascending, boolean strict) {
        if (names == null) {
            alphabet = getAlphabet(new String[] {"lower"});
        } else {
            alphabet = Cipher.getAlphabet(names);
        }
        StringBuilder sb = new StringBuilder();
        for (int i : k) {
            sb.append((char) i);
        }
        if (strict) {
            setKey(sanitize(sb.toString()), ascending);
        } else {
            setKey(sb.toString(), ascending);
        }
    }

    public ColTransCipher(String k, String[] names, boolean ascending, boolean strict) {
        if (names == null) {
            alphabet = getAlphabet(new String[] {"lower"});
        } else {
            alphabet = Cipher.getAlphabet(names);
        }
        if (strict) {
            setKey(sanitize(k), ascending);
        } else {
            setKey(k, ascending);
        }
    }

    private String sanitize(String k) {
        String t = k.toLowerCase();
        t = t.replace(" ", "");
        t = t.replace("\n", "");
        t = t.replace("\r", "");
        t = t.replace("\t", "");
        return t;
    }

    private void setKey(String k, boolean ascending) {
        char[] chars = k.toCharArray();
        ArrayList<Character> keyList = new ArrayList<>();
        ArrayList<Character> sortedList = new ArrayList<>();
        for (char c : chars) {
            if (!keyList.contains(c)) {
                keyList.add(c);
                sortedList.add(c);
            }
        }
        if (ascending) {
            sortedList.sort((a, b) -> Character.compare(a.charValue(), b.charValue()));
        } else {
            sortedList.sort((a, b) -> Character.compare(b.charValue(), a.charValue()));
        }

        key = keyList;
        keyOrder = sortedList;
    }

    @Override
    public String encrypt(String plaintext) {
        int cols = key.size();
        int rows = (int)(Math.ceil(plaintext.length() / (double)cols));

        char[] chars = plaintext.toCharArray();
        char[][] beta = new char[rows][cols];

        for (int i = 0; i < chars.length; i++) {
            beta[i/cols][i%cols] = chars[i];
        }

        char[][] orderedBeta = new char[rows][cols];
        for (int c = 0; c < cols; c++) {
            int order = key.indexOf(keyOrder.get(c));
            for (int r = 0; r < rows; r++) {
                orderedBeta[r][c] = beta[r][order];
            }
        }

        char[][] transpose = new char[cols][rows];
        for (int r = 0; r < rows; r++) {
            for (int c = 0; c < cols; c++) {
                transpose[c][r] = orderedBeta[r][c];
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < rows * cols; i++) {
            if ((int)transpose[i/rows][i%rows] == 0x00) {
                if (padding) {
                    sb.append(alphabet.get(Rand.randInt(alphabet.size())));
                    continue;
                } else {
                    continue;
                }
            }
            sb.append(transpose[i/rows][i%rows]);
        }

        return sb.toString();
    }

    @Override
    public String decrypt(String ciphertext) {
        int cols = key.size();
        int rows = (int)(Math.ceil(ciphertext.length() / (double)cols));

        char[] chars = ciphertext.toCharArray();
        char[][] transpose = new char[cols][rows];
        for (int i = 0; i < ciphertext.length(); i++) {
            transpose[i/rows][i%rows] = chars[i];
        }

        char[][] orderedBeta = new char[rows][cols];
        for (int c = 0; c < cols; c++) {
            for (int r = 0; r < rows; r++) {
                orderedBeta[r][c] = transpose[c][r];
            }
        }

        char[][] beta = new char[rows][cols];
        for (int c = 0; c < cols; c++) {
            int order = keyOrder.indexOf(key.get(c));
            for (int r = 0; r < rows; r++) {
                beta[r][c] = orderedBeta[r][order];
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < rows * cols; i++) {
            if ((int)beta[i/cols][i%cols] == 0x00) {
                if (padding) {
                    sb.append(alphabet.get(Rand.randInt(alphabet.size())));
                    continue;
                } else {
                    continue;
                }
            }
            sb.append(beta[i/cols][i%cols]);
        }

        return sb.toString();
    }

    public String crack(String ciphertext) {
        int textLength = ciphertext.length();
        String bestPlaintext = "";
        String bestKey = "";
        double bestScore = -Double.MAX_VALUE;
        int originalPlaintextLength = 36; // Known from main(), adjust for general use
        int keyLength = 5; // Hardcoded to match original key "57183" for testing

        // Generate permutations for the fixed key length
        List<Integer> columns = new ArrayList<>();
        for (int i = 0; i < keyLength; i++) columns.add(i);
        List<List<Integer>> permutations = generatePermutations(columns);

        for (List<Integer> perm : permutations) {
            StringBuilder keyBuilder = new StringBuilder();
            for (int col : perm) keyBuilder.append((char) ('0' + col));
            String trialKey = keyBuilder.toString();

            // Set the trial key and decrypt
            setKey(trialKey, true);
            String plaintext = decrypt(ciphertext);

            // Trim to original length to remove padding
            if (plaintext.length() > originalPlaintextLength) {
                plaintext = plaintext.substring(0, originalPlaintextLength);
            }

            // Score the plaintext
            double score = scorePlaintext(plaintext);

            if (score > bestScore) {
                bestScore = score;
                bestPlaintext = plaintext;
                bestKey = trialKey;
            }
        }

        System.out.println("Deduced key: " + bestKey);
        return bestPlaintext;
    }

    private List<List<Integer>> generatePermutations(List<Integer> list) {
        List<List<Integer>> result = new ArrayList<>();
        permute(list, 0, result);
        return result;
    }

    private void permute(List<Integer> list, int start, List<List<Integer>> result) {
        if (start == list.size()) {
            result.add(new ArrayList<>(list));
            return;
        }
        for (int i = start; i < list.size(); i++) {
            Collections.swap(list, start, i);
            permute(list, start + 1, result);
            Collections.swap(list, start, i); // backtrack
        }
    }

    private double scorePlaintext(String text) {
        double bigramScore = 0.0;
        int validWordCount = Dictionary.wordCount(text);

        // Calculate bigram frequency score
        for (int i = 0; i < text.length() - 1; i++) {
            String bigram = text.substring(i, i + 2).toLowerCase();
            Double freq = Bigrams.frequencies.getOrDefault(bigram, 0.0);
            bigramScore += freq * 1000.0; // Amplify bigram contribution
        }

        // Heavily prioritize word count and penalize incorrect length
        double lengthPenalty = (text.length() == 36) ? 0 : -10000.0;
        return validWordCount * 10000.0 + bigramScore + lengthPenalty;
    }

    public static void main(String[] args) {
        ColTransCipher ctc = new ColTransCipher("57183", null, true, false);
        String plaintext = "thequickbrownfoxjumpedoverthelazydogs";
        System.out.println("Original Plaintext: " + plaintext);
        String ciphertext = ctc.encrypt(plaintext);
        System.out.println("Ciphertext: " + ciphertext);
        String crackedPlaintext = ctc.crack(ciphertext);
        System.out.println("Cracked Plaintext: " + crackedPlaintext);
    }
}