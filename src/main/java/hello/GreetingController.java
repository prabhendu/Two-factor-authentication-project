package hello;

//import java.io.Console;
//import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Controller;
import org.apache.log4j.Logger;
//import org.bouncycastle.crypto.OutputLengthException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
public class GreetingController {

    private static final String template = "Hello, %s!";
    //private final AtomicLong counter = new AtomicLong();
    
    private static final Logger log = Logger.getLogger(GreetingController.class.getName());

    @RequestMapping("/prabhendu")
    public @ResponseBody Greeting prabhendu(@RequestParam(value="name", defaultValue="World") String name) {
    	log.info("Hello logging..Prabhendu in Greeting...buckle up");
    	return new Greeting("test", false,
                            String.format(template, name));
    }
    
    @RequestMapping(method=RequestMethod.POST ,value = "/greeting")
    public @ResponseBody Greeting greeting(@RequestBody InputModel test) throws Exception {
    	
    	log.info("ID : " + test.getUsername());
    	log.info("fingerprint : " + test.getFingerprint());
    	log.info("password : " + test.getPassword());
    	log.info("latency");
    	String username = test.getUsername();
    	String password = test.getPassword();
    	long fingerprint = test.getFingerprint();
    	int[] latency = test.getLatency();
    	
    	if((latency.length < 15) || (password.length()<8)) {
    		return new Greeting(String.format(template, username.toString()), false,
                    String.format("Need atleast 8 Char password"));
    	}
    	
    	for(int i=0;i<latency.length;i++) {
    		log.info(latency[i]);
    	}
    	log.info("prabhendu" + latency.length);
    	//TODO - set up back-end program to take in values and compute hardened password
    	SecLogin secLogin = new SecLogin();
    	Greeting result = secLogin.parseMain(username,password,fingerprint,latency);
    	String response ="";
    	if(result.getAttempt() == true) {
    		log.info("Login success");
    		response += result.getQuote();
    	} else {
    		log.info("Login fail");
    		response += result.getQuote();
    	}
    	//TODO - back-end processing call
    	
    	return result;
    }
    
}


