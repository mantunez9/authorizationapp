package isdcm.authorizationapp;

import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.finder.AttributeFinder;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.impl.CurrentEnvModule;
import com.sun.xacml.finder.impl.FilePolicyModule;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AuthorizationModule {

    public static void main(String[] args) {

        FilePolicyModule policyModule = new FilePolicyModule();
        policyModule.addPolicy("/path/to/policy.xml");

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

        //RequestCtx request = new RequestCtx(subjects, resourceAttrs, actionAttrs, environmentAttrs);

        try (InputStream input = new FileInputStream("myfile.txt")) {
            OutputStream response = pdp.evaluate(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
