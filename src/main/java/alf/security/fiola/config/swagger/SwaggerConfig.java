package alf.security.fiola.config.swagger;

import java.util.ArrayList;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMethod;

import alf.security.fiola.utility.properties.PropertiesConstants;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.ParameterBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.builders.ResponseMessageBuilder;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.service.Parameter;
import springfox.documentation.service.ResponseMessage;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig {

	private ArrayList<ResponseMessage> responseMessageBuilders = new ArrayList<>();

	@Bean
	public Docket apiDocket() {
		// Adding Header
		java.util.List<Parameter> aParameters = new ArrayList<>();
		ParameterBuilder aParameterBuilder = new ParameterBuilder();

		aParameterBuilder.name("Content-Type").description("Content Type").modelRef(new ModelRef("string"))
				.parameterType("header").defaultValue(MediaType.APPLICATION_JSON.toString()).required(false).build();
		aParameters.add(aParameterBuilder.build());
		aParameterBuilder = new ParameterBuilder();
		aParameterBuilder.name("Authorization").description("Login Session ID").modelRef(new ModelRef("string"))
				.parameterType("header").required(true).build();
		aParameters.add(aParameterBuilder.build());

		/**
		 * @note flag enable/disable swagger: true in dev false in production
		 */
		boolean enableSwagger = PropertiesConstants.isSwaggerEnable.equalsIgnoreCase("1") ? true : false;

		return new Docket(DocumentationType.SWAGGER_2).apiInfo(apiInfo()).useDefaultResponseMessages(false)
				.globalResponseMessage(RequestMethod.GET, getResponseMessageBuilders())
				.globalResponseMessage(RequestMethod.POST, getResponseMessageBuilders()).select()
				.apis(RequestHandlerSelectors.basePackage("bca.mycore.svc")).paths(PathSelectors.any()).build()
				.globalOperationParameters(aParameters).enable(enableSwagger);
	}

	private ApiInfo apiInfo() {
		return new ApiInfoBuilder().title(PropertiesConstants.appCode)
				.contact(new Contact("Chandra Wijaya", "www.bca.co.id", "chandra_wijaya@bca.co.id"))
				.description(PropertiesConstants.appDesc).version(PropertiesConstants.appVersion).license(PropertiesConstants.appLicense)
				.build();
	}

	private ArrayList<ResponseMessage> getResponseMessageBuilders() {
		// 200 global success message has not work yet
		responseMessageBuilders
				.add(new ResponseMessageBuilder().code(200).message("200 global success message").build());
		responseMessageBuilders.add(new ResponseMessageBuilder().code(404).message("404 global error message").build());
		responseMessageBuilders.add(new ResponseMessageBuilder().code(403).message("403 global error message").build());

		return responseMessageBuilders;
	}

}
