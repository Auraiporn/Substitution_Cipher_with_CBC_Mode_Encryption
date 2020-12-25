import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

public class Test {
    public static void main (String [] args) throws NoSuchAlgorithmException {
        /** To run the program
         *  java Test <<k value>>
         *  if k value is not given from the command line argument, the default k value is equal to 20.
         *  java Test
         */
        int k = 0;
        if(args.length == 1) {
            k = Integer.parseInt (args[0]);
            System.out.println ("k value is: " + k);
            start(k);
        }
        if(args.length != 1) {
            k = 20;
            System.out.println ("The default k value that represents substitution cipher shift will be given the value of " + k + ".");
            start (k);
        }
    }
    static void start (int k) throws NoSuchAlgorithmException {
        Scanner keyboard = new Scanner (System.in);
        System.out.print("Please enter the message to be encrypted: ");
        String message = keyboard.nextLine ();
        System.out.println ("Bytes of ascii of entered message: "+ Arrays.toString (message.getBytes ()));

        CBC cbc = new CBC(message,k);  // The class CBC will first generate random iv and obtain the plaintext from user input

        System.out.println ("Ascii of IV is:       "+ cbc.printASCII_char (cbc.getInitialize_vector ())     + "           The length of iv: " + cbc.getInitialize_vector ().length +
                "\nIV in Hexadecimal:    "+ cbc.bytes_to_hexadecimal (cbc.getInitialize_vector ())+ "   IV in Binary: " + cbc.printBinary (cbc.getInitialize_vector ()) );
        System.out.print ("The length of plain text is: " + cbc.getPlaintext ().length +
                "\nBytes of plaintext(p0,p1,p2,p3,..pn): "+ Arrays.toString (cbc.getPlaintext ()) + "\n");
        System.out.println ("\n*************************  Begin cipher substitution with CBC mode ******************************");
        ArrayList<Byte> ciphertext_ArrayList = cbc.substitution_cipher_with_CBC (cbc.getPlaintext (), cbc.getInitialize_vector (), k); // Perform cipher substitution with CBC mode
        byte [] ciphertext = cbc.arrayList_to_bytes_array (ciphertext_ArrayList);
        System.out.print ("Plaintext(p0, p1, p2,...,pn) in hexadecimal and in binary:  (" + cbc.bytes_to_hexadecimal (cbc.getPlaintext ()) + ")  (" + cbc.printBinary (cbc.getPlaintext ()) +
                ")\nCiphertext(iv, c0, c1, c2, ...,cn) in hexadecimal and in binary: (" + cbc.bytes_to_hexadecimal (ciphertext) + ")  (" + cbc.printBinary (ciphertext) +
                ")\nCiphertext in bytes of ASCII is: " );
        cbc.display_ArrayList (ciphertext_ArrayList);
        //_______________________________________________________ Display the result_____________________________________________________________
        System.out.println ("\n\n********************************* Result *******************************************************" +
                "\nA message to be encrypted is: \t" + message +
                "\nAn encrypted message is: \t\t" + cbc.printASCII_char (ciphertext) +
                "\n*************************************************************************************************" +
                "\n\nNote:\nSize of original message is:  " + message.getBytes ().length + "\tSize of ciphertext is: " + ciphertext_ArrayList.size () +
                "\nPadding size is:              " +  cbc.getPadding () + "\t\tPlaintext size is:     " + cbc.getPlaintext ().length);
    }
}