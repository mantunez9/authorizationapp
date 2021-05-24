package isdcm.authorizationapp;

import com.sun.xacml.attr.DateAttribute;
import com.sun.xacml.attr.IntegerAttribute;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.ctx.Subject;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class RequestBuilder {

    public static Set setupSubjects(List<Request> requestList) throws URISyntaxException, ParseException {
        HashSet attributes = getAttributes(requestList);
        HashSet subjects = new HashSet();
        subjects.add(new Subject(attributes));
        return subjects;
    }

    public static Set setupResource(List<Request> requestList) throws URISyntaxException, ParseException {
        HashSet resource = getAttributes(requestList);
        return resource;
    }

    public static Set setupAction(List<Request> requestList) throws URISyntaxException, ParseException {
        HashSet action = getAttributes(requestList);
        return action;
    }

    private static HashSet getAttributes(List<Request> requestList) throws URISyntaxException, ParseException {

        HashSet attribute = new HashSet();

        for (Request attributes : requestList) {

            URI resourceId = new URI(attributes.getAttribute());

            switch (attributes.getType()) {
                case "string":
                    attribute.add(new com.sun.xacml.ctx.Attribute(resourceId, null, null, new StringAttribute(attributes.getAttributeValue())));
                    break;
                case "integer":
                    attribute.add(new com.sun.xacml.ctx.Attribute(resourceId, null, null, new IntegerAttribute(Integer.parseInt(attributes.getAttributeValue()))));
                    break;
                case "date":
                    attribute.add(new com.sun.xacml.ctx.Attribute(resourceId, null, null, new DateAttribute(new SimpleDateFormat("yyyy-MM-dd").parse(attributes.getAttributeValue()))));
                    break;
            }

        }

        return attribute;

    }

}
