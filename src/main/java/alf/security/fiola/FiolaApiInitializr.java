package alf.security.fiola;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication(exclude = {MongoAutoConfiguration.class})
@ComponentScan({ "alf.security.fiola.config", "alf.security.fiola.utility", "alf.security.fiola.internals" })
public class FiolaApiInitializr {

	public static void main(String[] args) {
		SpringApplication.run(FiolaApiInitializr.class, args);
	}

}
