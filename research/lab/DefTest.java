/*
 * §6 - which JAXP hardening switches actually stop XXE on this JDK.
 *   javac DefTest.java && java DefTest      (run XxeSchemes first to create tmp/secret.txt)
 */
import javax.xml.parsers.*;
import javax.xml.XMLConstants;
import org.xml.sax.InputSource;
import java.io.*;
import java.util.function.Consumer;

public class DefTest {

    static String dir = new File("tmp").getAbsolutePath();

    static void t(String label, Consumer<DocumentBuilderFactory> cfg) {
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"" + dir + "/secret.txt\">]><r>&xxe;</r>";
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            cfg.accept(f);
            DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(null);
            String out = b.parse(new InputSource(new StringReader(xml)))
                          .getDocumentElement().getTextContent().trim().replace("\n", "\\n");
            System.out.printf("%-48s => %s%n", label, out.isEmpty() ? "(blocked: empty)" : "LEAKED: " + out);
        } catch (Exception e) {
            System.out.printf("%-48s => BLOCKED (%s)%n", label, e.getClass().getSimpleName());
        }
    }

    static void feature(DocumentBuilderFactory f, String name, boolean v) {
        try { f.setFeature(name, v); } catch (Exception ignored) { }
    }

    public static void main(String[] a) {
        System.out.println("Java " + System.getProperty("java.version"));
        t("default DocumentBuilderFactory",       f -> { });
        t("FEATURE_SECURE_PROCESSING = true",     f -> feature(f, XMLConstants.FEATURE_SECURE_PROCESSING, true));
        t("setXIncludeAware(false) only",         f -> f.setXIncludeAware(false));
        t("disallow-doctype-decl = true",         f -> feature(f, "http://apache.org/xml/features/disallow-doctype-decl", true));
        t("external-general-entities = false",    f -> feature(f, "http://xml.org/sax/features/external-general-entities", false));
        t("setExpandEntityReferences(false)",     f -> f.setExpandEntityReferences(false));
        t("ACCESS_EXTERNAL_DTD = \"\"",             f -> { try { f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, ""); } catch (Exception ignored) { } });
    }
}
