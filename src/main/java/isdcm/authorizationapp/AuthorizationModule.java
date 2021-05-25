package isdcm.authorizationapp;

import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.ctx.RequestCtx;
import com.sun.xacml.finder.AttributeFinder;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.impl.CurrentEnvModule;
import com.sun.xacml.finder.impl.FilePolicyModule;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.wso2.balana.Balana;
import org.wso2.balana.finder.AttributeFinderModule;
import org.wso2.balana.finder.ResourceFinder;
import org.wso2.balana.finder.ResourceFinderModule;
import org.wso2.balana.finder.impl.FileBasedPolicyFinderModule;
import org.xml.sax.SAXException;

import javax.swing.*;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class AuthorizationModule {

    private static Balana balana;

    public static final String ATTRIBUTE = "Attribute";
    public static final String ATTRIBUTE_VALUE = "AttributeValue";
    public static final String ATTRIBUTE_ID = "AttributeId";
    public static final String DATA_TYPE = "DataType";

    public static int menu() {

        int selection;
        Scanner input = new Scanner(System.in);

        System.out.println("\nChoose from these choices");
        System.out.println("-------------------------\n");
        System.out.println("1 - Sun Authorization");
        System.out.println("2 - Balana Authorization");
        System.out.println("3 - Signature");
        System.out.println("4 - Quit");

        selection = input.nextInt();
        return selection;

    }

    public static void main(String[] args) throws Exception {

        boolean conditional = true;

        while (conditional) {

            switch (menu()) {

                case 1:
                    sunAuthorization();
                    break;
                case 2:
                    balanaAuthorization();
                    break;
                case 3:
                    signature();
                    break;
                case 4:
                    conditional = false;

            }

        }

    }

    private static void sunAuthorization() throws Exception {

        FilePolicyModule policyModule = new FilePolicyModule();
        policyModule.addPolicy(abrirArchivo());

        CurrentEnvModule envModule = new CurrentEnvModule();

        PolicyFinder policyFinder = new PolicyFinder();
        Set policyModules = new HashSet();
        policyModules.add(policyModule);
        policyFinder.setModules(policyModules);

        AttributeFinder attrFinder = new AttributeFinder();
        List attrModules = new ArrayList();
        attrModules.add(envModule);
        attrFinder.setModules(attrModules);

        PDP pdp = new PDP(new PDPConfig(attrFinder, policyFinder, null));

        Document xmlDocument = inputFileToDoc(abrirArchivo());
        NodeList list = xmlDocument.getElementsByTagName(ATTRIBUTE);

        List<Request> subjects = new ArrayList<>();
        List<Request> resources = new ArrayList<>();
        List<Request> actions = new ArrayList<>();

        for (int i = 0; i < list.getLength(); ++i) {

            switch (xmlDocument.getElementsByTagName(ATTRIBUTE).item(i).getParentNode().getNodeName()) {

                case "Subject": {
                    subjects.add(
                            Request.builder()
                                    .attribute(xmlDocument.getElementsByTagName(ATTRIBUTE).item(i).getAttributes().getNamedItem(ATTRIBUTE_ID).getTextContent())
                                    .attributeValue(xmlDocument.getElementsByTagName(ATTRIBUTE_VALUE).item(i).getTextContent())
                                    .type(xmlDocument.getElementsByTagName(ATTRIBUTE).item(i).getAttributes().getNamedItem(DATA_TYPE).getTextContent().split("#")[1])
                                    .build()
                    );
                    break;
                }

                case "Resource": {
                    resources.add(
                            Request.builder()
                                    .attribute(xmlDocument.getElementsByTagName(ATTRIBUTE).item(i).getAttributes().getNamedItem(ATTRIBUTE_ID).getTextContent())
                                    .attributeValue(xmlDocument.getElementsByTagName(ATTRIBUTE_VALUE).item(i).getTextContent())
                                    .type(xmlDocument.getElementsByTagName(ATTRIBUTE).item(i).getAttributes().getNamedItem(DATA_TYPE).getTextContent().split("#")[1])
                                    .build()
                    );
                    break;
                }

                case "Action": {
                    actions.add(
                            Request.builder()
                                    .attribute(xmlDocument.getElementsByTagName(ATTRIBUTE).item(i).getAttributes().getNamedItem(ATTRIBUTE_ID).getTextContent())
                                    .attributeValue(xmlDocument.getElementsByTagName(ATTRIBUTE_VALUE).item(i).getTextContent())
                                    .type(xmlDocument.getElementsByTagName(ATTRIBUTE).item(i).getAttributes().getNamedItem(DATA_TYPE).getTextContent().split("#")[1])
                                    .build()
                    );
                    break;
                }

            }

        }

        RequestCtx request = new RequestCtx(RequestBuilder.setupSubjects(subjects), RequestBuilder.setupResource(resources), RequestBuilder.setupAction(actions), new HashSet());
        pdp.evaluate(request).encode(new FileOutputStream("src/main/resources/response.xml"));
        System.out.println("\n======================== XACML Response ===================");
        System.out.println(new String(Files.readAllBytes(Paths.get("src/main/resources/response.xml"))));

    }

    private static Document inputFileToDoc(String fileName) throws Exception {

        File xmlFile = new File(fileName);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        return dBuilder.parse(xmlFile);

    }

    private static String abrirArchivo() {

        JFileChooser file = new JFileChooser();
        file.setCurrentDirectory(new File("."));
        file.showOpenDialog(null);
        return file.getSelectedFile().getPath();

    }

    private static void balanaAuthorization() throws Exception {

        initBalana();
        String request = new String(Files.readAllBytes(Paths.get(abrirArchivo())));
        org.wso2.balana.PDP pdp = getPDPNewInstance();
        String response = pdp.evaluate(request);
        System.out.println("\n======================== XACML Response ===================");
        System.out.println(response);

    }

    private static void initBalana() {

        String path = abrirArchivo();
        String policyLocation = path;
        System.setProperty(FileBasedPolicyFinderModule.POLICY_DIR_PROPERTY, policyLocation);
        balana = Balana.getInstance();

    }

    private static org.wso2.balana.PDP getPDPNewInstance() {

        org.wso2.balana.PDPConfig pdpConfig = balana.getPdpConfig();

        org.wso2.balana.finder.AttributeFinder attributeFinder = pdpConfig.getAttributeFinder();
        List<AttributeFinderModule> finderModules = attributeFinder.getModules();
        attributeFinder.setModules(finderModules);

        ResourceFinder resourceFinder = pdpConfig.getResourceFinder();
        List<ResourceFinderModule> resourceModules = resourceFinder.getModules();
        resourceFinder.setModules(resourceModules);

        return new org.wso2.balana.PDP(new org.wso2.balana.PDPConfig(attributeFinder, pdpConfig.getPolicyFinder(), resourceFinder, true));

    }

    private static void signature() throws ParserConfigurationException, IOException, SAXException, MarshalException, XMLSignatureException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableEntryException, TransformerException {

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        Reference ref = fac.newReference
                ("", fac.newDigestMethod(DigestMethod.SHA1, null),
                        Collections.singletonList
                                (fac.newTransform
                                        (Transform.ENVELOPED, (TransformParameterSpec) null)),
                        null, null);

        SignedInfo si = fac.newSignedInfo
                (fac.newCanonicalizationMethod
                                (CanonicalizationMethod.INCLUSIVE,
                                        (C14NMethodParameterSpec) null),
                        fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                        Collections.singletonList(ref));

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("C:/Users/mantu/.keystore"), "isdcm12".toCharArray());
        KeyStore.PrivateKeyEntry keyEntry =
                (KeyStore.PrivateKeyEntry) ks.getEntry
                        ("isdcm", new KeyStore.PasswordProtection("isdcm12".toCharArray()));
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse
                (new FileInputStream(abrirArchivo()));

        DOMSignContext dsc = new DOMSignContext
                (keyEntry.getPrivateKey(), doc.getDocumentElement());

        XMLSignature signature = fac.newXMLSignature(si, ki);

        signature.sign(dsc);

        OutputStream os = new FileOutputStream("signedDocument.xml");
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));

    }

}
