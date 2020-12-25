import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CBC {
    private final int BLOCK_SIZE = 8;
    private final char[] hexadecimal_array = "0123456789ABCDEF".toCharArray();
    private byte[] plaintext, initialize_vector;
    private int padding, k;

    /** A constructor of CBC class which is responsible of initializing the fields of the class to perform Substitution Cipher with Cipher Block Chaining Mode Encryption
     * @param message a message to be encrypted
     * @param k the kth shifting amount
     * */
    public CBC (String message, int k) throws NoSuchAlgorithmException {
        this.plaintext = padding_process (message.getBytes (), message);
        this.padding = padding;
        this.initialize_vector = generate_random_iv ();
        this.k = k;
    }

    /** Accessor for CBC class */
    public int getPadding(){
        return this.padding;
    }
    public byte[] getPlaintext(){
        return this.plaintext;
    }
    public byte[] getInitialize_vector(){
        return this.initialize_vector;
    }

    /** Generate a random initialize vector
     * @return iv_bytes a byte array of a random initialize vector
     * */
    public byte[] generate_random_iv () throws NoSuchAlgorithmException {
        String characters_of_ascii = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        String iv = secureRandom.ints(BLOCK_SIZE, 0, characters_of_ascii.length()).mapToObj(i -> characters_of_ascii.charAt(i))
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append).toString();
        byte [] iv_bytes = iv.getBytes ();
        return iv_bytes;
    }

    /** Determine the end of the input. If there is any padding should be applied, the method will add the missing bytes to complete the last plaintext to be 8 bytes.
     *  For example, let x be any ascii bytes in the range of ascii table
     *      - If the last plaintext has 8 bytes, the padding size returns 8.
     *          However, it simply determines the end of the string, but it does not add anything to the end of the last plaintext.
     *
     *     - If the last plaintext has 7 bytes, the padding size returns 1.
     *          It means that there is one more byte needed to be filled to complete 8 bytes, so the last plaintext will be [x,x,x,x,x,x,x,1].
     *
     *      - If the last plaintext has 6 bytes, the padding size returns 2.
     *          It means that there are 2 more bytes needed to be filled to complete 8 bytes, so the last plaintext will be [x,x,x,x,x,x,2,2].
     *
     *     - If the last plaintext has 5 bytes, the padding size returns 3.
     *          It means that there are 3 more bytes needed to be filled to complete 8 bytes, so the last plaintext will be [x,x,x,x,x,3,3,3].
     *
     *     - If the last plaintext has 4 bytes, the padding size returns 4.
     *          It means that there are 4 more bytes needed to be filled to complete 8 bytes, so the last plaintext will be [x,x,x,x,4,4,4,4].
     *
     *     - If the last plaintext has 3 bytes, the padding size returns 5.
     *          It means that there are 5 more bytes needed to be filled to complete 8 bytes, so the last plaintext will be [x,x,x,5,5,5,5,5].
     *
     *     - If the last plaintext has 2 bytes, the padding size returns 6.
     *          It means that there are 6 more bytes needed to be filled to complete 8 bytes, so the last plaintext will be [x,x,6,6,6,6,6,6].
     *
     *     - If the last plaintext has 1 byte, the padding size returns 7.
     *          It means that there are 7 more bytes needed to be filled to complete 8 bytes, so the last plaintext will be [x,7,7,7,7,7,7,7].
     * @param ascii_of_message a byte array of an input message
     * @param message a String of input message
     * @return plain_text a byte array of plaintext, if the last block does not have 8 bytes, it will including a padding size.
     * */
    public byte[] padding_process (byte [] ascii_of_message, String message){
        int plain_text_length = ascii_of_message.length;
        System.out.println ("The size of entered message is: "+ plain_text_length);
        if(plain_text_length % BLOCK_SIZE != 0){
            plain_text_length = plain_text_length + (BLOCK_SIZE- (plain_text_length % BLOCK_SIZE));
        }
        byte[] plain_text = new byte[plain_text_length];
        padding = BLOCK_SIZE - (message.length () % BLOCK_SIZE);
        System.out.println ("Padding: " + (byte) padding + " bytes");
        System.arraycopy (ascii_of_message, 0, plain_text, 0, ascii_of_message.length);
        for(int i=ascii_of_message.length; i<plain_text.length;i++){
            plain_text[i]= (byte) padding;
        }
        return plain_text;
    }

    /** Perform Substitution Cipher with Cipher Block Chaining Mode Algorithm
     * @param plain_text a byte array of plaintext
     * @param iv a byte array of an initialize vector which has the size of 8 bytes
     * @param k the kth shifting amount
     * @return array_of_ciphertext an ArrayList of ciphertext, where ciphertext contains iv + c0 + c1 + c2 + ... + cn
     * */
    public ArrayList<Byte> substitution_cipher_with_CBC (byte[] plain_text, byte[] iv,int k){
        ArrayList <Byte> ciphertext = new ArrayList<Byte> ();  // Encrypted message --> iv + c0 + c1 + c2 + ... + cn
        int number_of_blocks = plain_text.length/BLOCK_SIZE;
        System.out.println ("Split the plaintext into a block of " + BLOCK_SIZE + " bytes, so there are " + number_of_blocks +" blocks of plaintext.");
        byte[] plaintext_p0_to_pn = new byte[BLOCK_SIZE];
        int plaintext_block_quantity = plain_text.length;
        try {
            byte []  c = null;
            for(int j=0; j< number_of_blocks; j++) {
                for (int i = 0; i < plaintext_block_quantity; i += BLOCK_SIZE) {
                    int checkUpperLimit = Math.min (plaintext_block_quantity, i + BLOCK_SIZE);
                    if (i == 0 && j == 0) {
                        plaintext_p0_to_pn = Arrays.copyOfRange (plain_text, i, checkUpperLimit);
                        System.out.println ("p0: \t\t\t" + bytes_to_hexadecimal (plaintext_p0_to_pn) + " (in hexadecimal)");
                        System.out.println ("p0: \t\t\t" + printASCII_char (plaintext_p0_to_pn));

                        byte[] ivXORp0 = xor (iv, plaintext_p0_to_pn);
                        System.out.println ("ivXORp0: \t\t" + bytes_to_hexadecimal (ivXORp0) + " (in hexadecimal)");
                        System.out.println ("ivXORp0: \t\t" + printASCII_char (ivXORp0));
                        ciphertext.addAll (bytes_array_to_ArrayList (iv));                                              // Add iv to encrypted message

                        c = encrypt (ivXORp0, k);
                        System.out.println ("c0: \t\t\t" + bytes_to_hexadecimal (c) + " (in hexadecimal)");
                        System.out.println ("c0: \t\t\t" + printASCII_char (c));
                        ciphertext.addAll (bytes_array_to_ArrayList (c));                                               // Add c0 to encrypted message
                        System.out.println ("");
                    }
                    else if (i == BLOCK_SIZE*(j+1)) {                                                                   // i == i*2 --> i ==8, 16, 24, 32, 40, 48,..., 8*number_of_blocks
                        plaintext_p0_to_pn = Arrays.copyOfRange (plain_text, i, checkUpperLimit);
                        System.out.println ("p"+ (j+1) + ": \t\t\t" + bytes_to_hexadecimal (plaintext_p0_to_pn) + " (in hexadecimal)");
                        System.out.println ("p"+ (j+1) + ": \t\t\t" + printASCII_char (plaintext_p0_to_pn));

                        byte[] cXORp = xor (c, plaintext_p0_to_pn);
                        System.out.println ("p" + (j+1) + " XOR c" + j +": \t\t" + bytes_to_hexadecimal (cXORp) + " (in hexadecimal)");
                        System.out.println ("p" + (j+1)  + " XOR c" + j +": \t\t" + printASCII_char (cXORp));

                        c = encrypt (cXORp, k);
                        System.out.println ("c" + (j+1) +": \t\t\t" + bytes_to_hexadecimal (c) + " (in hexadecimal)");
                        System.out.println ("c" + (j+1) +": \t\t\t" + printASCII_char (c));
                        ciphertext.addAll (bytes_array_to_ArrayList (c));                                               // add c1, c2, ..., cn to encrypted message
                        System.out.println ("");
                    }
                }
            }
        } catch (RuntimeException e){
            e.printStackTrace ();
        }
        return ciphertext;
    }

    /** Encrypt the input message using a substitution cipher with the Cipher Block Chaining mode.
     * @param k a number, k representing the substitution cipher shift, such that each ASCII character would be encrypted by the kth character ahead of it in the alphabet.
     * @param iv a pointer to the initializing vector
     * @return ciphertext returns an encrypted message
     * */
    public byte[] encrypt(byte[] iv, int k){
        byte[] ciphertext = new byte[BLOCK_SIZE];
        for(int i=0;i<iv.length;i++){
            ciphertext[i] = (byte) (iv[i] + k);
        }
        return ciphertext;
    }

    /** Perform XORing operation between two byte arrays
     * @param a a byte array to computed XOR
     * @param b a byte array to computed XOR
     * @return result returns the result of XORing operations of two byte arrays
     * */
    public byte[] xor(byte[] a, byte[]b){
        byte[] result = new byte[a.length];
        for(int i=0;i<a.length;i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /** Convert an ArrayList of Byte to a byte array
     * @param ciphertext an ArrayList of Byte to be converted to a byte array
     * @return array_of_ciphertext a byte array of ciphertext
     * */
    public byte[] arrayList_to_bytes_array(ArrayList<Byte> ciphertext) {
        final int n = ciphertext.size();
        byte array_of_ciphertext[] = new byte[n];
        for (int i = 0; i < n; i++) {
            array_of_ciphertext[i] = ciphertext.get(i);
        }
        return array_of_ciphertext;
    }

    /** Convert bytes array into an ArrayList of Byte
     * @param array_of_byte a byte array to be added to ArrayList
     * @return arrayList an ArrayList of bytes array
     * */
    public ArrayList<Byte> bytes_array_to_ArrayList(byte[] array_of_byte) {
        ArrayList<Byte> arrayList = new ArrayList<Byte> (array_of_byte.length);
        for(byte b : array_of_byte) {
            arrayList.add(b);
        }
        return arrayList;
    }

    /** Display an ArrayList
     * @param p_arrayList an ArrayList of Byte to be displayed
     * */
    public void display_ArrayList(List<Byte> p_arrayList){
        for (int i = 0; i < p_arrayList.size(); i ++) {
            System.out.print (" "+p_arrayList.get (i));
        }
    }

    /** Display ASCII characters from a byte array
     * @param b a byte array to be printed in ASCII characters
     * @return s returns the String of ASCII characters
     * */
    public String printASCII_char(byte [] b){
        String s = new String (b);
        return s;
    }

    /** Display a byte array into a binary representation
     * @param a a byte array to be displayed in binary
     * @return s returns the String of binary representation of ASCII bytes
     * */
    public String printBinary(byte[] a){
        String[] result = new String[a.length];
        for(int i=0;i<a.length;i++){
            result[i] = Integer.toBinaryString(a[i]);
        }
        String s = String.join ("", result);
        return s;
    }

    /** Display a byte array into a hexadecimal representation
     * @param bytes a byte array to be displayed in hexadecimal
     * @return s returns the String of hexadecimal representation of ASCII bytes
     * */
    public String bytes_to_hexadecimal (byte[] bytes) {
        char[] hex_chars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hex_chars[j * 2] = hexadecimal_array[v >>> 4];
            hex_chars[j * 2 + 1] = hexadecimal_array[v & 0x0F];
        }
        String s =  new String(hex_chars);
        return s;
    }


}

