package org.cloudifysource.dsl.rest;

import org.cloudifysource.dsl.utils.RecipePathResolver;

public class RestRecipePathResolver extends RecipePathResolver {

	private static final String DEFAULT_ROOT_PATH = "/root/gigaspaces/tools/cli/../../work";

	public RestRecipePathResolver() {
		super();
		DEFAULT_SERVICES_PATH = "/cloudify_recipes_clone/services";
		DEFAULT_APPS_PATH = "/cloudify_recipes_clone/apps";
		DEFAULT_CLOUDS_PATH = "/clouds";
	}
	
	protected String getHomeDir() {
		return DEFAULT_ROOT_PATH;
	}

}
