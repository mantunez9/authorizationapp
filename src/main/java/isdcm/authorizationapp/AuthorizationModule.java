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

import javax.swing.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class AuthorizationModule {

    public static final String ATTRIBUTE = "Attribute";
    public static final String ATTRIBUTE_VALUE = "AttributeValue";
    public static final String ATTRIBUTE_ID = "AttributeId";
    public static final String DATA_TYPE = "DataType";

    public static int menu() {

        int selection;
        Scanner input = new Scanner(System.in);

        System.out.println("Choose from these choices");
        System.out.println("-------------------------\n");
        System.out.println("1 - Sun Authorization");
        System.out.println("2 - Balana Authorization");
        System.out.println("3 - Quit");

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
                case 3:
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
        file.showOpenDialog(null);
        return file.getSelectedFile().getPath();
    }

}
