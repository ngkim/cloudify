/*******************************************************************************
 * Copyright (c) 2013 GigaSpaces Technologies Ltd. All rights reserved
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *******************************************************************************/
package org.cloudifysource.rest.controllers;

import static org.cloudifysource.rest.ResponseConstants.FAILED_TO_LOCATE_LUS;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;

import net.jini.core.discovery.LookupLocator;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.cloudifysource.domain.Application;
import org.cloudifysource.domain.ComputeDetails;
import org.cloudifysource.domain.Service;
import org.cloudifysource.domain.cloud.Cloud;
import org.cloudifysource.dsl.internal.CloudifyConstants;
import org.cloudifysource.dsl.internal.CloudifyConstants.InvocationStatus;
import org.cloudifysource.dsl.internal.CloudifyErrorMessages;
import org.cloudifysource.dsl.internal.CloudifyMessageKeys;
import org.cloudifysource.dsl.internal.DSLApplicationCompilationResult;
import org.cloudifysource.dsl.internal.DSLServiceCompilationResult;
import org.cloudifysource.dsl.internal.DSLUtils;
import org.cloudifysource.dsl.internal.ServiceReader;
import org.cloudifysource.dsl.internal.packaging.Packager;
import org.cloudifysource.dsl.rest.RestRecipePathResolver;
import org.cloudifysource.dsl.rest.request.ConfigApplicationRequest;
import org.cloudifysource.dsl.rest.request.InstallApplicationRequest;
import org.cloudifysource.dsl.rest.request.InstallServiceRequest;
import org.cloudifysource.dsl.rest.request.InvokeCustomCommandRequest;
import org.cloudifysource.dsl.rest.request.SetApplicationAttributesRequest;
import org.cloudifysource.dsl.rest.request.SetServiceAttributesRequest;
import org.cloudifysource.dsl.rest.request.SetServiceInstanceAttributesRequest;
import org.cloudifysource.dsl.rest.request.SetServiceInstancesRequest;
import org.cloudifysource.dsl.rest.request.UpdateApplicationAttributeRequest;
import org.cloudifysource.dsl.rest.response.ApplicationDescription;
import org.cloudifysource.dsl.rest.response.ConfigApplicationResponse;
import org.cloudifysource.dsl.rest.response.DeleteApplicationAttributeResponse;
import org.cloudifysource.dsl.rest.response.DeleteServiceAttributeResponse;
import org.cloudifysource.dsl.rest.response.DeleteServiceInstanceAttributeResponse;
import org.cloudifysource.dsl.rest.response.DeploymentEvent;
import org.cloudifysource.dsl.rest.response.DeploymentEvents;
import org.cloudifysource.dsl.rest.response.DeploymentResult;
import org.cloudifysource.dsl.rest.response.DeploymentStatus;
import org.cloudifysource.dsl.rest.response.GetApplicationAttributesResponse;
import org.cloudifysource.dsl.rest.response.GetServiceAttributesResponse;
import org.cloudifysource.dsl.rest.response.GetServiceInstanceAttributesResponse;
import org.cloudifysource.dsl.rest.response.InstallApplicationResponse;
import org.cloudifysource.dsl.rest.response.InstallServiceResponse;
import org.cloudifysource.dsl.rest.response.InvokeInstanceCommandResponse;
import org.cloudifysource.dsl.rest.response.InvokeServiceCommandResponse;
import org.cloudifysource.dsl.rest.response.ServiceDescription;
import org.cloudifysource.dsl.rest.response.ServiceDetails;
import org.cloudifysource.dsl.rest.response.ServiceInstanceDetails;
import org.cloudifysource.dsl.rest.response.ServiceInstanceMetricsData;
import org.cloudifysource.dsl.rest.response.ServiceInstanceMetricsResponse;
import org.cloudifysource.dsl.rest.response.ServiceMetricsResponse;
import org.cloudifysource.dsl.rest.response.UninstallApplicationResponse;
import org.cloudifysource.dsl.rest.response.UninstallServiceResponse;
import org.cloudifysource.dsl.rest.response.UploadResponse;
import org.cloudifysource.dsl.utils.ServiceUtils;
import org.cloudifysource.rest.ResponseConstants;
import org.cloudifysource.rest.RestConfiguration;
import org.cloudifysource.rest.controllers.exceptions.CLIStatusException;
import org.cloudifysource.rest.controllers.helpers.ControllerHelper;
import org.cloudifysource.rest.controllers.helpers.PropertiesOverridesMerger;
import org.cloudifysource.rest.controllers.util.ApplicationResolver;
import org.cloudifysource.rest.controllers.util.NameAndPackedFileResolver;
import org.cloudifysource.rest.controllers.util.PreparedApplicationPackageResolver;
import org.cloudifysource.rest.deploy.ApplicationDeployerRequest;
import org.cloudifysource.rest.deploy.ApplicationDeployerRunnable;
import org.cloudifysource.rest.deploy.DeploymentConfig;
import org.cloudifysource.rest.deploy.ElasticDeploymentCreationException;
import org.cloudifysource.rest.deploy.ElasticProcessingUnitDeploymentFactory;
import org.cloudifysource.rest.deploy.ElasticProcessingUnitDeploymentFactoryImpl;
import org.cloudifysource.rest.deploy.ServiceApplicationDependentProperties;
import org.cloudifysource.rest.events.EventsUtils;
import org.cloudifysource.rest.events.cache.AdminBasedGridServiceContainerProvider;
import org.cloudifysource.rest.events.cache.EventsCache;
import org.cloudifysource.rest.events.cache.EventsCacheKey;
import org.cloudifysource.rest.events.cache.EventsCacheValue;
import org.cloudifysource.rest.exceptions.ResourceNotFoundException;
import org.cloudifysource.rest.repo.UploadRepo;
import org.cloudifysource.rest.util.ApplicationDescriptionFactory;
import org.cloudifysource.rest.util.IsolationUtils;
import org.cloudifysource.rest.validators.InstallApplicationValidationContext;
import org.cloudifysource.rest.validators.InstallApplicationValidator;
import org.cloudifysource.rest.validators.InstallServiceValidationContext;
import org.cloudifysource.rest.validators.InstallServiceValidator;
import org.cloudifysource.rest.validators.SetServiceInstancesValidationContext;
import org.cloudifysource.rest.validators.SetServiceInstancesValidator;
import org.cloudifysource.rest.validators.UninstallApplicationValidationContext;
import org.cloudifysource.rest.validators.UninstallApplicationValidator;
import org.cloudifysource.rest.validators.UninstallServiceValidationContext;
import org.cloudifysource.rest.validators.UninstallServiceValidator;
import org.cloudifysource.restclient.RestClient;
import org.cloudifysource.restclient.exceptions.RestClientException;
import org.cloudifysource.security.CloudifyAuthorizationDetails;
import org.cloudifysource.security.CustomPermissionEvaluator;
import org.cloudifysource.utilitydomain.data.ServiceInstanceAttemptData;
import org.cloudifysource.utilitydomain.kvstorage.spaceentries.ApplicationCloudifyAttribute;
import org.cloudifysource.utilitydomain.kvstorage.spaceentries.InstanceCloudifyAttribute;
import org.cloudifysource.utilitydomain.kvstorage.spaceentries.ServiceCloudifyAttribute;
import org.jgrapht.DirectedGraph;
import org.jgrapht.alg.CycleDetector;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.traverse.TopologicalOrderIterator;
import org.openspaces.admin.Admin;
import org.openspaces.admin.AdminException;
import org.openspaces.admin.gsc.GridServiceContainer;
import org.openspaces.admin.gsm.GridServiceManager;
import org.openspaces.admin.internal.admin.InternalAdmin;
import org.openspaces.admin.internal.pu.DefaultProcessingUnitInstance;
import org.openspaces.admin.internal.pu.InternalProcessingUnit;
import org.openspaces.admin.internal.pu.InternalProcessingUnitInstance;
import org.openspaces.admin.internal.pu.elastic.GridServiceContainerConfig;
import org.openspaces.admin.pu.ProcessingUnit;
import org.openspaces.admin.pu.ProcessingUnitInstance;
import org.openspaces.admin.pu.ProcessingUnits;
import org.openspaces.admin.pu.elastic.ElasticStatefulProcessingUnitDeployment;
import org.openspaces.admin.pu.elastic.ElasticStatelessProcessingUnitDeployment;
import org.openspaces.admin.pu.elastic.config.ManualCapacityScaleConfigurer;
import org.openspaces.admin.pu.elastic.topology.ElasticDeploymentTopology;
import org.openspaces.admin.space.ElasticSpaceDeployment;
import org.openspaces.core.GigaSpace;
import org.openspaces.core.util.MemoryUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * This controller is responsible for retrieving information about deployments.
 * It is also the entry point for deploying services and application. <br>
 * <br>
 * The response body will always return in a JSON representation of the
 * {@link org.cloudifysource.dsl.rest.response.Response} Object. <br>
 * A controller method may return the
 * {@link org.cloudifysource.dsl.rest.response.Response} Object directly. in
 * this case this return value will be used as the response body. Otherwise, an
 * implicit wrapping will occur. the return value will be inserted into
 * {@code Response#setResponse(Object)}. other fields of the
 * {@link org.cloudifysource.dsl.rest.response.Response} object will be filled
 * with default values. <br>
 * <h1>Important</h1> {@code @ResponseBody} annotations are not permitted. <br>
 * <br>
 * <h1>Possible return values</h1> 200 - OK<br>
 * 400 - controller throws an exception<br>
 * 500 - Unexpected exception<br>
 * <br>
 * 
 * @see {@link org.cloudifysource.rest.interceptors.ApiVersionValidationAndRestResponseBuilderInterceptor}
 * @author elip , ahmadm
 * @since 2.5.0
 * 
 */

@Controller
@RequestMapping(value = "/{version}/deployments")
public class DeploymentsController extends BaseRestController {

	private static final Logger logger = Logger
			.getLogger(DeploymentsController.class.getName());
	private static final int MAX_NUMBER_OF_EVENTS = 100;
	private static final int REFRESH_INTERVAL_MILLIS = 500;
	private static final long WAIT_FOR_PU_SECONDS = 30;
	private static final int WAIT_FOR_MANAGED_TIMEOUT_SECONDS = 10;
	private static final int PU_DISCOVERY_TIMEOUT_SEC = 8;
	private static final int LOCAL_CLOUD_INSTANCE_MEMORY_MB = 512;

	private static final String REST_API_SERVER_URL = "http://127.0.0.1:8100";
	private static final String REST_API_SERVER_VER = "2.7.1";
	private static final String REST_API_SERVER_USR = "";
	private static final String REST_API_SERVER_PWD = "";

	private static String debugMsg = "";

	// ngkim: to be removed
	// To keep track of deployment status
	// Set to 0 when UTM configuration has requested
	private static int tmpTotalDeploymentStep = 7;
	private static int tmpDeploymentStatus = 0;
	private static Map<String, DeploymentStatus> deploymentMap;
	
//	private static Map<String, Integer> deploymentStatus;

	private static Date lastDate;
//	private static int[] delayPerStep = {0, 120, 30, 42, 33, 22, 45};
//	private static int[] delayPerStep = {0, 120, 30, 42, 33, 22, 45, 30};
	private static int[] delayPerStep = {0, 5, 4, 3, 3, 4, 2, 2};

	@Autowired
	private RestConfiguration restConfig;
	@Autowired
	private UploadRepo repo;
	@Autowired
	private InstallServiceValidator[] installServiceValidators = new InstallServiceValidator[0];
	@Autowired
	private UninstallServiceValidator[] uninstallServiceValidators = new UninstallServiceValidator[0];
	@Autowired
	private InstallApplicationValidator[] installApplicationValidators = new InstallApplicationValidator[0];
	@Autowired
	private UninstallApplicationValidator[] uninstallApplicationValidators = new UninstallApplicationValidator[0];
	@Autowired
	private SetServiceInstancesValidator[] setServiceInstancesValidators = new SetServiceInstancesValidator[0];

	protected GigaSpace gigaSpace;
	private Admin admin;
	private CustomPermissionEvaluator permissionEvaluator;
	private final ExecutorService serviceUndeployExecutor = Executors
			.newFixedThreadPool(10);
	private EventsCache eventsCache;
	private ControllerHelper controllerHelper;
	private File extractedFodler;

	/**
	 * Initialization.
	 * 
	 * @throws RestErrorException
	 *             If failed to create upload directory.
	 */
	@PostConstruct
	public void init() throws RestErrorException {
		gigaSpace = restConfig.getGigaSpace();
		permissionEvaluator = restConfig.getPermissionEvaluator();
		File restTempFolder = restConfig.getRestTempFolder();
		repo.setBaseDir(restTempFolder);
		repo.init();
		this.admin = restConfig.getAdmin();
		this.eventsCache = new EventsCache(admin);
		this.controllerHelper = new ControllerHelper(gigaSpace, admin);
		this.extractedFodler = new File(restTempFolder,
				CloudifyConstants.EXTRACTED_FILES_FOLDER_NAME);
		extractedFodler.mkdirs();
		extractedFodler.deleteOnExit();
	}

	/**
	 * Provides various meta data about the service.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @return Meta data about the service.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the requested service does not exist.
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/metadata", method = RequestMethod.GET)
	public ServiceDetails getServiceDetails(@PathVariable final String appName,
			@PathVariable final String serviceName)
			throws ResourceNotFoundException {

		final ProcessingUnit processingUnit = controllerHelper.getService(
				appName, serviceName);
		final ServiceDetails serviceDetails = new ServiceDetails();
		serviceDetails.setName(serviceName);
		serviceDetails.setApplicationName(appName);
		serviceDetails
				.setNumberOfInstances(processingUnit.getInstances().length);

		final List<String> instanceNames = new ArrayList<String>();
		for (final ProcessingUnitInstance instance : processingUnit
				.getInstances()) {
			instanceNames.add(instance.getProcessingUnitInstanceName());
		}
		serviceDetails.setInstanceNames(instanceNames);

		return serviceDetails;
	}

	/**
	 * Basic test to see if the rest is connected properly.
	 * 
	 * @throws RestErrorException
	 *             Thrown in case the rest does not identify any lookup
	 *             services.
	 */
	@RequestMapping(value = "/testrest", method = RequestMethod.GET)
	public void test() throws RestErrorException {

		if (restConfig.getAdmin().getLookupServices().getSize() > 0) {
			return;
		}
		final String groups = Arrays
				.toString(restConfig.getAdmin().getGroups());
		final String locators = Arrays.toString(restConfig.getAdmin()
				.getLocators());
		throw new RestErrorException(FAILED_TO_LOCATE_LUS, groups, locators);
	}

	/******
	 * Waits for a single instance of a service to become available. NOTE:
	 * currently only uses service name as processing unit name.
	 * 
	 * @param applicationName
	 *            not used.
	 * @param serviceName
	 *            the service name.
	 * @param timeout
	 *            the timeout period to wait for the processing unit, and then
	 *            the PU instance.
	 * @param timeUnit
	 *            the time unit used to wait for the processing unit, and then
	 *            the PU instance.
	 * @return true if instance is found, false if instance is not found in the
	 *         specified period.
	 */
	public boolean waitForServiceInstance(final String applicationName,
			final String serviceName, final long timeout,
			final TimeUnit timeUnit) {

		// this should be a very fast lookup, since the service was already
		// successfully deployed
		final String absolutePUName = ServiceUtils.getAbsolutePUName(
				applicationName, serviceName);
		final ProcessingUnit pu = restConfig.getAdmin().getProcessingUnits()
				.waitFor(absolutePUName, timeout, timeUnit);
		if (pu == null) {
			return false;
		}

		// ignore the time spent on PU lookup, as it should be failry short.
		return pu.waitFor(1, timeout, timeUnit);

	}

	/**
	 * Retrieves events based on deployment id. The deployment id may be of
	 * service or application. In the case of an application deployment id, all
	 * services events will be returned.
	 * 
	 * @param deploymentId
	 *            The deployment id given at install time.
	 * @param from
	 *            The starting index.
	 * @param to
	 *            The finish index.
	 * @return {@link org.cloudifysource.dsl.rest.response.DeploymentEvents} -
	 *         The deployment events.
	 * @throws Throwable
	 *             Thrown in case of any error.
	 */
	@RequestMapping(value = "{deploymentId}/events", method = RequestMethod.GET)
	public DeploymentEvents getDeploymentEvents(
			@PathVariable final String deploymentId,
			@RequestParam(required = false, defaultValue = "1") final int from,
			@RequestParam(required = false, defaultValue = "-1") final int to)
			throws Throwable {

		if (deploymentId == null) {
			throw new RestErrorException(
					CloudifyErrorMessages.MISSING_DEPLOYMENT_ID.getName(),
					"getDeploymentEvents");
		}
		verifyDeploymentIdExists(deploymentId);

		// limit the default number of events returned to the client.
		int actualTo = to;
		if (to == -1) {
			actualTo = from + MAX_NUMBER_OF_EVENTS;
		}

		EventsCacheKey key = new EventsCacheKey(deploymentId);
		logger.fine(EventsUtils.getThreadId()
				+ " Received request for events [" + from + "]-[" + to
				+ "] . key : " + key);
		EventsCacheValue value;
		try {
			value = eventsCache.get(key);
		} catch (final ExecutionException e) {
			throw e.getCause();
		}

		// we don't want another request to modify our object during this
		// calculation.
		synchronized (value.getMutex()) {
			if (!EventsUtils.eventsPresent(value.getEvents(), from, actualTo)) {
				// enforce time restriction on refresh operations.
				long now = System.currentTimeMillis();
				if (now - value.getLastRefreshedTimestamp() > REFRESH_INTERVAL_MILLIS) {
					// refresh the cache for this deployment.
					eventsCache.refresh(key);
				}
			} else {
				logger.fine(EventsUtils.getThreadId()
						+ " Found all relevant events in cache.");
			}

			// return the events. this MAY or MAY NOT be the complete set of
			// events requested.
			// request for specific events is treated as best effort. no
			// guarantees all events are returned.
			DeploymentEvents deploymentEvents = EventsUtils
					.extractDesiredEvents(value.getEvents(), from, actualTo);
			logger.finest("Returning events " + deploymentEvents
					+ " for deployment id " + deploymentId + " to the "
					+ "client");
			return deploymentEvents;
		}
	}

	/********************************
	 * Returns the last event for a specific operation.
	 * 
	 * @param deploymentId
	 *            the operation ID.
	 * @return the last event received for this operation. May be an empty set.
	 * @throws Throwable
	 *             in case of an error while retrieving events.
	 */
	@RequestMapping(value = "{deploymentId}/events/last", method = RequestMethod.GET)
	public DeploymentEvent getLastDeploymentEvent(
			@PathVariable final String deploymentId) throws Throwable {

		verifyDeploymentIdExists(deploymentId);

		logger.fine("Received request for last deployment event for deployment "
				+ deploymentId);

		EventsCacheKey key = new EventsCacheKey(deploymentId);
		EventsCacheValue value = eventsCache.get(key);
		int lastEventIndex = value.getLastEventIndex();
		List<DeploymentEvent> events = getDeploymentEvents(deploymentId,
				lastEventIndex, lastEventIndex + 1).getEvents();
		switch (events.size()) {
		case 0:
			// no events. return empty
			return new DeploymentEvent();
		case 1:
			// we only have the old last event. return this one.
			return events.get(0);
		case 2:
			// we have the old last event plus a new one. return the new one.
			return events.get(1);
		default:
			throw new IllegalStateException(
					"Unexpected event list size for request of events ["
							+ lastEventIndex + "]-[" + (lastEventIndex + 1)
							+ "] : " + events.size());
		}
	}

	private void verifyDeploymentIdExists(final String deploymentId)
			throws ResourceNotFoundException {
		if (logger.isLoggable(Level.FINE)) {
			logger.fine("[validateDeploymentIdExists] validating deploymentId:"
					+ deploymentId);
		}
		/*
		 * events cache.
		 */
		EventsCacheKey key = new EventsCacheKey(deploymentId);
		EventsCacheValue value = eventsCache.getIfExists(key);
		if (value == null) {
			/*
			 * processing units.
			 */
			if (logger.isLoggable(Level.FINE)) {
				logger.fine("[validateDeploymentIdExists] - "
						+ "The deploymentId doesn't exist in the eventsCache,  "
						+ "searching for a processing unit with that deployment id ["
						+ deploymentId + "]");
			}
			ProcessingUnits processingUnits = admin.getProcessingUnits();
			for (ProcessingUnit pu : processingUnits) {
				String puDeploymentId = (String) pu.getBeanLevelProperties()
						.getContextProperties()
						.get(CloudifyConstants.CONTEXT_PROPERTY_DEPLOYMENT_ID);
				if (deploymentId.equals(puDeploymentId)) {
					return;
				}
			}
			throw new ResourceNotFoundException("Deployment id " + deploymentId);
		}
	}

	/**
	 * Sets application level attributes for the given application.
	 * 
	 * @param appName
	 *            The application name.
	 * @param attributesRequest
	 *            Request body, specifying the attributes names and values.
	 * @throws RestErrorException
	 *             Thrown in case the request body is empty.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the application does not exist.
	 */
	@RequestMapping(value = "/{appName}/attributes", method = RequestMethod.POST)
	public void setApplicationAttributes(@PathVariable final String appName,
			@RequestBody final SetApplicationAttributesRequest attributesRequest)
			throws RestErrorException, ResourceNotFoundException {
		// valid application
		controllerHelper.getApplication(appName);

		if (attributesRequest == null
				|| attributesRequest.getAttributes() == null) {
			throw new RestErrorException(
					CloudifyMessageKeys.EMPTY_REQUEST_BODY_ERROR.getName());
		}

		// set attributes
		controllerHelper.setAttributes(appName, null, null,
				attributesRequest.getAttributes());

	}

	/**
	 * Sets the number of instances of a service to a given value. This
	 * operation is only allowed for services that are marked as Elastic
	 * (defined in the recipe). Note: set instances does NOT support
	 * multi-tenancy. You should only use set-instances with dedicated machine
	 * SLA. Manually scaling a multi-tenant service will cause unexpected
	 * side-effect.
	 * 
	 * @param applicationName
	 *            the application name.
	 * 
	 * @param serviceName
	 *            the service name.
	 * 
	 * @param request
	 *            the request details.
	 * 
	 * @throws RestErrorException
	 *             When the service is not elastic.
	 * @throws ResourceNotFoundException
	 *             If the service is not found.
	 */
	@RequestMapping(value = "/{applicationName}/services/{serviceName}/count", method = RequestMethod.POST)
	@PreAuthorize("isFullyAuthenticated() and hasPermission(#authGroups, 'deploy')")
	public void setServiceInstances(@PathVariable final String applicationName,
			@PathVariable final String serviceName,
			@RequestBody final SetServiceInstancesRequest request)
			throws RestErrorException, ResourceNotFoundException {

		if (logger.isLoggable(Level.INFO)) {
			logger.info("Scaling request for service: " + applicationName + "."
					+ serviceName + " to " + request.getCount() + " instances");
		}

		final ProcessingUnit pu = this.controllerHelper.getService(
				applicationName, serviceName);

		if (pu == null) {
			throw new RestErrorException(
					ResponseConstants.FAILED_TO_LOCATE_SERVICE, serviceName);
		}

		validateSetInstances(applicationName, serviceName, request, pu);

		if (permissionEvaluator != null) {
			final String puAuthGroups = pu
					.getBeanLevelProperties()
					.getContextProperties()
					.getProperty(CloudifyConstants.CONTEXT_PROPERTY_AUTH_GROUPS);
			final Authentication authentication = SecurityContextHolder
					.getContext().getAuthentication();
			final CloudifyAuthorizationDetails authDetails = new CloudifyAuthorizationDetails(
					authentication);
			permissionEvaluator.verifyPermission(authDetails, puAuthGroups,
					"deploy");
		}

		final int count = request.getCount();
		logger.info("Scaling " + pu.getName() + " to " + count + " instances");

		Cloud cloud = restConfig.getCloud();

		if (cloud == null) {
			// Manual scale by number of instances
			pu.scale(new ManualCapacityScaleConfigurer().memoryCapacity(
					LOCAL_CLOUD_INSTANCE_MEMORY_MB * count,
					MemoryUnit.MEGABYTES).create());

		} else {

			final Map<String, String> properties = ((InternalProcessingUnit) pu)
					.getElasticProperties();
			final GridServiceContainerConfig gscConfig = new GridServiceContainerConfig(
					properties);
			final long cloudExternalProcessMemoryInMB = gscConfig
					.getMaximumMemoryCapacityInMB();

			pu.scale(ElasticScaleConfigFactory.createManualCapacityScaleConfig(
					(int) (cloudExternalProcessMemoryInMB * count), 0,
					request.isLocationAware(), true));
		}
	}

	private void validateSetInstances(final String applicationName,
			final String serviceName, final SetServiceInstancesRequest request,
			final ProcessingUnit pu) throws RestErrorException {
		SetServiceInstancesValidationContext validationContext = new SetServiceInstancesValidationContext();
		validationContext.setApplicationName(applicationName);
		validationContext.setServiceName(serviceName);
		validationContext.setCloud(this.restConfig.getCloud());
		validationContext.setAdmin(admin);
		validationContext.setRequest(request);
		validationContext.setProcessingUnit(pu);

		for (SetServiceInstancesValidator validator : setServiceInstancesValidators) {
			validator.validate(validationContext);
		}
	}

	/**
	 * Delete an instance level attribute.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @param instanceId
	 *            The instance id.
	 * @param attributeName
	 *            The attribute name.
	 * @return The previous value for this attribute in the response.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the requested service or service instance does
	 *             not exist.
	 * @throws RestErrorException
	 *             Thrown in case the requested attribute name is empty.
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/instances/{instanceId}/attributes/{attributeName}", method = RequestMethod.DELETE)
	public DeleteServiceInstanceAttributeResponse deleteServiceInstanceAttribute(
			@PathVariable final String appName,
			@PathVariable final String serviceName,
			@PathVariable final Integer instanceId,
			@PathVariable final String attributeName)
			throws ResourceNotFoundException, RestErrorException {
		// valid service
		controllerHelper.getService(appName, serviceName);

		// logger - request to delete attributes
		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to delete attribute "
					+ attributeName + " of instance Id " + instanceId
					+ " of service "
					+ ServiceUtils.getAbsolutePUName(appName, serviceName)
					+ " of application " + appName);
		}

		// get delete attribute returned previous value
		final Object previous = controllerHelper.deleteAttribute(appName,
				serviceName, instanceId, attributeName);

		// create response object
		final DeleteServiceInstanceAttributeResponse siar = new DeleteServiceInstanceAttributeResponse();
		// set previous value
		siar.setPreviousValue(previous);
		// return response object
		return siar;

	}

	/**
	 * Provides various meta data about the service instance.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @param instanceId
	 *            The instance id.
	 * @return Meta data about the service instance.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the service or service instance does not
	 *             exist.
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/instances/{instanceId}/metadata", method = RequestMethod.GET)
	public ServiceInstanceDetails getServiceInstanceDetails(
			@PathVariable final String appName,
			@PathVariable final String serviceName,
			@PathVariable final Integer instanceId)
			throws ResourceNotFoundException {
		// get processingUnit instance
		final ProcessingUnitInstance pui = controllerHelper.getServiceInstance(
				appName, serviceName, instanceId);

		// get USM details
		final org.openspaces.pu.service.ServiceDetails usmDetails = pui
				.getServiceDetailsByServiceId("USM");
		// get attributes details
		final Map<String, Object> puiAttributes = usmDetails.getAttributes();

		// get private ,public IP
		final String privateIp = controllerHelper
				.getServiceInstanceEnvVariable(pui,
						CloudifyConstants.GIGASPACES_AGENT_ENV_PRIVATE_IP);
		final String publicIp = controllerHelper.getServiceInstanceEnvVariable(
				pui, CloudifyConstants.GIGASPACES_AGENT_ENV_PUBLIC_IP);

		// machine details
		final String hardwareId = controllerHelper
				.getServiceInstanceEnvVariable(pui,
						CloudifyConstants.GIGASPACES_CLOUD_HARDWARE_ID);
		final String machineId = controllerHelper
				.getServiceInstanceEnvVariable(pui,
						CloudifyConstants.GIGASPACES_CLOUD_MACHINE_ID);
		final String imageId = controllerHelper.getServiceInstanceEnvVariable(
				pui, CloudifyConstants.GIGASPACES_CLOUD_IMAGE_ID);
		final String templateName = controllerHelper
				.getServiceInstanceEnvVariable(pui,
						CloudifyConstants.GIGASPACES_CLOUD_TEMPLATE_NAME);

		// return new instance
		final ServiceInstanceDetails sid = new ServiceInstanceDetails();
		// set service instance details
		sid.setApplicationName(appName);
		sid.setServiceName(serviceName);
		sid.setServiceInstanceName(pui.getName());

		// set service instance machine details
		sid.setHardwareId(hardwareId);
		sid.setImageId(imageId);
		sid.setInstanceId(instanceId);
		sid.setMachineId(machineId);
		sid.setPrivateIp(privateIp);
		sid.setProcessDetails(puiAttributes);
		sid.setPublicIp(publicIp);
		sid.setTemplateName(templateName);

		return sid;

	}

	/**
	 * Deploys an application to the service grid. An application is consisted
	 * of a group of services that might have dependencies between themselves.
	 * The application will be deployed according to the dependency order
	 * defined in the application file and deployed asynchronously if possible.
	 * 
	 * Prior to calling this method, the application recipe must be packed and
	 * uploaded through the upload controller. Each upload yields a unique key,
	 * used by this method. Uploading the recipe is mandatory. Optional uploads
	 * allowing to customize the deployment: cloud configuration – File or
	 * directory containing cloud configuration to be used for this application
	 * overrides – File containing properties to be used to override the
	 * properties of the application and its services cloud overrides – File
	 * containing properties to be used to override the current cloud
	 * configuration for this application and its services
	 * 
	 * The request body values are: Application name – mandatory – The
	 * application name applcationFileUploadKey – mandatory – key of the
	 * uploaded packed recipe file cloudConfigurationUploadKey – optional – the
	 * key of the uploaded cloud configuration applicationOverridesUploadKey –
	 * optional – the key of the uploaded overrides file cloudOverridesUploadKey
	 * – optional – the key of the uploaded cloud overrides file authGroups –
	 * optional – Used when bootstrapped in secured mode. Set the auth-groups
	 * the application will be exposed to. If empty will use the calling user's
	 * auth-groups selfHealing – mandatory – if true, there will be an attempt
	 * to restart the recipe in case a problem occurred in its life-cycle.
	 * Otherwise, no attempt to recover will made if the recipe fails to execute
	 * debugAll – optional – defaults to False. This flag is used for recipe
	 * debugging. It indicates whether all lifecycle events should have a
	 * breakpoint. debugEvents – optional. This flag is used for recipe
	 * debugging. Indicates which lifecycle events should have a breakpoint.
	 * debugMode – optional. This flag is used for recipe debugging. It
	 * indicates the debug mode to use (either 'instead', 'after' or 'onError')
	 * 
	 * @param appName
	 *            The application name.
	 * @param request
	 *            install application request.
	 * @return an install application response.
	 * @throws RestErrorException
	 *             indicates a failure to install the application
	 * 
	 */
	@RequestMapping(value = "/{appName}", method = RequestMethod.POST)
	@PreAuthorize("isFullyAuthenticated() and hasPermission(#request.getAuthGroups(), 'deploy')")
	public InstallApplicationResponse installApplication(
			@PathVariable final String appName,
			@RequestBody final InstallApplicationRequest request)
			throws RestErrorException {

		// get the application file
		final String applcationFileUploadKey = request
				.getApplcationFileUploadKey();
		final File applicationFile = getFromRepo(applcationFileUploadKey,
				CloudifyMessageKeys.WRONG_APPLICTION_FILE_UPLOAD_KEY.getName(),
				appName);

		// get the application overrides file
		final String applicationOverridesFileKey = request
				.getApplicationOverridesUploadKey();
		final File applicationOverridesFile = getFromRepo(
				applicationOverridesFileKey,
				CloudifyMessageKeys.WRONG_APPLICTION_OVERRIDES_FILE_UPLOAD_KEY
						.getName(), appName);

		// construct application object
		DSLApplicationCompilationResult appReaderResult;
		try {
			appReaderResult = ServiceReader.getApplicationFromFile(
					applicationFile, applicationOverridesFile);
		} catch (final Exception e) {
			throw new RestErrorException("Failed reading application file."
					+ " Reason: " + e.getMessage(), e);
		}

		Application application = appReaderResult.getApplication();
		application.setName(appName);

		// perform validations
		validateInstallApplication(application, request,
				appReaderResult.getApplicationOverridesFile());

		// update effective authGroups
		String effectiveAuthGroups = getEffectiveAuthGroups(request
				.getAuthGroups());
		request.setAuthGroups(effectiveAuthGroups);

		// create install dependency order.
		final List<Service> services = createServiceDependencyOrder(application);

		// create a deployment ID that would be used across all services.
		final String deploymentID = UUID.randomUUID().toString();

		// remove any existing attributes for this application.
		deleteApplicationScopeAttributes(request.getApplicationName());

		// create the installer
		ApplicationDeployerRequest applicationDeployerRequest = new ApplicationDeployerRequest();
		applicationDeployerRequest.setAppDir(appReaderResult
				.getApplicationDir());
		applicationDeployerRequest.setAppFile(appReaderResult
				.getApplicationFile());
		applicationDeployerRequest.setAppPropertiesFile(appReaderResult
				.getApplicationPropertiesFile());
		applicationDeployerRequest.setAppOverridesFile(appReaderResult
				.getApplicationOverridesFile());
		applicationDeployerRequest.setController(this);
		applicationDeployerRequest.setDeploymentID(deploymentID);
		applicationDeployerRequest.setRequest(request);
		applicationDeployerRequest.setServices(services);

		final ApplicationDeployerRunnable installer = new ApplicationDeployerRunnable(
				applicationDeployerRequest);

		// install
		if (installer.isAsyncInstallPossibleForApplication()) {
			installer.run();
		} else {
			restConfig.getExecutorService().execute(installer);
		}

		// we wait for the pu so that after this method returns
		// we would be able to poll for events safely using the deployment-id.
		String firstServiceName = services.get(0).getName();
		String firstPuName = ServiceUtils.getAbsolutePUName(appName,
				firstServiceName);
		final boolean firstPuCreated = waitForPu(appName, firstServiceName,
				WAIT_FOR_PU_SECONDS, TimeUnit.SECONDS);
		if (!firstPuCreated) {
			throw new RestErrorException(
					CloudifyErrorMessages.FAILED_WAIT_FOR_PU.getName(),
					firstPuName);
		}

		// creating response
		final InstallApplicationResponse response = new InstallApplicationResponse();
		response.setDeploymentID(deploymentID);
		return response;
	}

	private File writeToProperties(File parent, String propertyFileName,
			Map<String, String> params) {
		FileOutputStream fos = null;
		PrintStream ps = null;

		File propertyFile = new File(parent, propertyFileName);
		try {
			fos = new FileOutputStream(propertyFile, false); // not append, overwrite
			ps = new PrintStream(fos);

			Iterator<Entry<String, String>> it = params.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<String, String> pairs = (Map.Entry<String, String>) it
						.next();
				ps.println(pairs.getKey() + "=" + pairs.getValue());
				it.remove(); // avoids a ConcurrentModificationException
			}

			if (ps != null)
				ps.close();
			if (fos != null)
				fos.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return propertyFile;
	}

	private String uploadFile(String fileName, File file) {
		String msg = "";

		RestClient restClient;
		try {
			restClient = new RestClient(new URL(REST_API_SERVER_URL),
					REST_API_SERVER_USR, REST_API_SERVER_PWD,
					REST_API_SERVER_VER);
			UploadResponse response = restClient.upload(fileName, file);
			msg = response.getUploadKey();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (RestClientException e) {
			e.printStackTrace();
		}

		return msg;
	}

	private NameAndPackedFileResolver getResolver(File applicationFile,
			File overrides) throws CLIStatusException {
		// this is a prepared package we can just use.
		if (applicationFile.isFile()) {
			if (applicationFile.getName().endsWith("zip")
					|| applicationFile.getName().endsWith("jar")) {
				return new PreparedApplicationPackageResolver(applicationFile,
						overrides);
			}
			throw new CLIStatusException("application_file_format_mismatch",
					applicationFile.getPath());
		}
		// this is an actual application directory
		return new ApplicationResolver(applicationFile, overrides);
	}

	private File resolveServiceDir(String svcName) {
		File svcDir = new File(svcName);
		// 1. resolve the path for the given service input
		final RestRecipePathResolver pathResolver = new RestRecipePathResolver();
		if (pathResolver.resolveService(svcDir)) {
			svcDir = pathResolver.getResolved();
		} else {
			// return null if not found
			svcDir = null;
			debugMsg += "resolveServiceDir, ServiceDir not found, "
					+ pathResolver.getPathsLooked().toString();
		}

		return svcDir;
	}

	private File resolveApplicationDir(String appName) {
		File applicationDir = new File(appName);
		// 1. resolve the path for the given service input
		final RestRecipePathResolver pathResolver = new RestRecipePathResolver();
		if (pathResolver.resolveApplication(applicationDir)) {
			applicationDir = pathResolver.getResolved();
		} else {
			// return null if not found
			applicationDir = null;
			debugMsg += "resolveApplicationDir, ApplicationDir not found, "
					+ pathResolver.getPathsLooked().toString();
		}

		return applicationDir;
	}
	
	private File getPackedFile(String appName, File applicationDir){
		File packedFile = null;
		
		try {
			// resolve packed file and application name
			final NameAndPackedFileResolver nameAndPackedFileResolver = getResolver(applicationDir, null);

			packedFile = nameAndPackedFileResolver.getPackedFile();

			debugMsg += "\npackedFile=";
			debugMsg += packedFile.getPath();
		} catch (Exception e) {
			debugMsg += e.getMessage();
		}
		
		return packedFile;
	}
	
	private File saveServiceProperties(String svcName, Map<String, String> params) {
		// 1. resolve the path for the given service input
		File svcDir = resolveServiceDir(svcName);

		// TODO: change to use service
		// String propertiesFileName =
		// DSLUtils.getPropertiesFileName(applicationFile,
		// DSLUtils.APPLICATION_DSL_FILE_NAME_SUFFIX);
		String propertiesFileName = "EndianUTM.config";
		debugMsg += propertiesFileName;

		// 1. create properties file
		// 2. write parameters into the properties files
//		File propertiesFile = writeToProperties(svcDir, propertiesFileName, params);
		writeToProperties(svcDir, propertiesFileName, params);

		return svcDir;
	}
	
	
	private String restInstallApplication(InstallApplicationRequest request, String deploymentID)
			throws RestErrorException {
		String appName = request.getApplicationName();
		String applicationFileUploadKey = request.getApplcationFileUploadKey();

		// get the application file
		final File applicationFile = getFromRepo(applicationFileUploadKey,
				CloudifyMessageKeys.WRONG_APPLICTION_FILE_UPLOAD_KEY.getName(),
				appName);

		// construct application object
		DSLApplicationCompilationResult appReaderResult;
		try {
			appReaderResult = ServiceReader.getApplicationFromFile(
					applicationFile, null);
		} catch (final Exception e) {
			throw new RestErrorException("Failed reading application file."
					+ " Reason: " + e.getMessage(), e);
		}

		Application application = appReaderResult.getApplication();
		application.setName(appName);

		// create install dependency order.
		final List<Service> services = createServiceDependencyOrder(application);

		// remove any existing attributes for this application.
		deleteApplicationScopeAttributes(appName);

		// create the installer
		ApplicationDeployerRequest applicationDeployerRequest = new ApplicationDeployerRequest();
		applicationDeployerRequest.setAppDir(appReaderResult
				.getApplicationDir());
		applicationDeployerRequest.setAppFile(appReaderResult
				.getApplicationFile());
		applicationDeployerRequest.setAppPropertiesFile(appReaderResult
				.getApplicationPropertiesFile());
		applicationDeployerRequest.setAppOverridesFile(appReaderResult
				.getApplicationOverridesFile());
		applicationDeployerRequest.setController(this);
		applicationDeployerRequest.setDeploymentID(deploymentID);
		applicationDeployerRequest.setRequest(request);
		applicationDeployerRequest.setServices(services);

		final ApplicationDeployerRunnable installer = new ApplicationDeployerRunnable(
				applicationDeployerRequest);

		// install
		if (installer.isAsyncInstallPossibleForApplication()) {
			installer.run();
		} else {
			restConfig.getExecutorService().execute(installer);
		}

		String firstServiceName = services.get(0).getName();
		String firstPuName = ServiceUtils.getAbsolutePUName(appName,
				firstServiceName);
		final boolean firstPuCreated = waitForPu(appName, firstServiceName,
				WAIT_FOR_PU_SECONDS, TimeUnit.SECONDS);
		if (!firstPuCreated) {
			throw new RestErrorException(
					CloudifyErrorMessages.FAILED_WAIT_FOR_PU.getName(),
					firstPuName);
		}

		return deploymentID;

	}
	
	private class UTMZone {
		private String ipAddress;
		private String broadcast;
		private String network;
		private String netmask;
		private String intf;
		
		public UTMZone(String ipAddr, String broad, String network, String netmask, String intf){
			this.ipAddress = ipAddr;
			this.broadcast = broad;
			this.network = network;
			this.netmask = netmask;
			this.intf = intf;
		}

		public String getIpAddress() {
			return ipAddress;
		}

		public void setIpAddress(String ipAddress) {
			this.ipAddress = ipAddress;
		}

		public String getBroadcast() {
			return broadcast;
		}

		public void setBroadcast(String broadcast) {
			this.broadcast = broadcast;
		}

		public String getNetwork() {
			return network;
		}

		public void setNetwork(String network) {
			this.network = network;
		}

		public String getNetmask() {
			return netmask;
		}

		public void setNetmask(String netmask) {
			this.netmask = netmask;
		}

		public String getIntf() {
			return intf;
		}

		public void setIntf(String intf) {
			this.intf = intf;
		}
		
		
	}
	
	private Map<String, String> utmConfig(UTMZone green, UTMZone orange, UTMZone red){
		Map<String, String> params = new HashMap<String, String>();
		
		params.put("ADMIN_PASSWORD", "endian");
		params.put("ROOT_PASSWORD", "endian");
		params.put("DOMAINNAME", "localdomain");
		
		params.put("GREEN_ADDRESS", green.getIpAddress());
		params.put("GREEN_BROADCAST", green.getBroadcast());
		params.put("GREEN_NETADDRESS", green.getNetwork());
		params.put("GREEN_NETMASK", green.getNetmask());
		
		params.put("ORANGE_ADDRESS", orange.getIpAddress());
		params.put("ORANGE_BROADCAST", orange.getBroadcast());
		params.put("ORANGE_NETADDRESS", orange.getNetwork());
		params.put("ORANGE_NETMASK", orange.getNetmask());
		
		params.put("RED_ADDRESS", red.getIpAddress());
		params.put("RED_BROADCAST", red.getBroadcast());
		params.put("RED_NETADDRESS", red.getNetwork());
		params.put("RED_NETMASK", red.getNetmask());
		
		return params;
	}
	
	@RequestMapping(value = "/applications/{appName}/configuration", method = RequestMethod.POST)
	@PreAuthorize("isFullyAuthenticated() and hasPermission(#request.getAuthGroups(), 'deploy')")
	public ConfigApplicationResponse configApplication(
			@PathVariable final String appName,
			@RequestBody final ConfigApplicationRequest request)
			throws RestErrorException {
		debugMsg = "";

		String adminPassword = request.getAdminPassword();
		String rootPassword = request.getRootPassword();
		String hostName = request.getHostName();
		String domainName = request.getDomainName();
		String deviceName = request.getDeviceName();

		String greenZoneIpAddress = request.getGreenZoneIpAddress();
		String greenZoneBroadcast = request.getGreenZoneBroadcast();
		String greenZoneNetwork = request.getGreenZoneNetwork();
		String greenZoneNetmask = request.getGreenZoneNetmask();
		String greenZoneInterface = request.getGreenZoneInterface();
		
		UTMZone greenZone = new UTMZone(greenZoneIpAddress, greenZoneBroadcast, greenZoneNetwork, greenZoneNetmask, greenZoneInterface);
		
		String orangeZoneIpAddress = request.getOrangeZoneIpAddress();
		String orangeZoneBroadcast = request.getOrangeZoneBroadcast();
		String orangeZoneNetwork = request.getOrangeZoneNetwork();
		String orangeZoneNetmask = request.getOrangeZoneNetmask();
		String orangeZoneInterface = request.getOrangeZoneInterface();
		
		UTMZone orangeZone = new UTMZone(orangeZoneIpAddress, orangeZoneBroadcast, orangeZoneNetwork, orangeZoneNetmask, orangeZoneInterface);

		String redZoneIpAddress = request.getRedZoneIpAddress();
		String redZoneBroadcast = request.getRedZoneBroadcast();
		String redZoneNetwork = request.getRedZoneNetwork();
		String redZoneNetmask = request.getRedZoneNetmask();
		String redZoneInterface = request.getRedZoneInterface();
		
		UTMZone redZone = new UTMZone(redZoneIpAddress, redZoneBroadcast, redZoneNetwork, redZoneNetmask, redZoneInterface);
		
		boolean isDeploy = request.isDeploy();

		Map<String, String> params = utmConfig(greenZone, orangeZone, redZone);
				
		// save properties into service configuration file
//		File svcDir = saveServiceProperties("endian_simple", params);
		saveServiceProperties("endian_simple", params);
		File packedFile = getPackedFile(appName, resolveApplicationDir(appName));

		String applicationFileUploadKey = uploadFile(packedFile.getName(), packedFile);

		// create a deployment ID that would be used across all services.
		final String deploymentID = UUID.randomUUID().toString();
		
		// 4. install applications
		try {
			// init deploymentMap
			if(deploymentMap == null) {
				deploymentMap = new HashMap<String, DeploymentStatus>();
			}
					
			DeploymentStatus status = new DeploymentStatus();

			int firstStep = 0;
			status.setTotalSteps(Integer.toString(tmpTotalDeploymentStep));
			
			status.setCurrentStep(new String(Integer.toString(firstStep)));
			status.setStatus("OK");
			status.setMessage(getStatusMessage(firstStep));
			status.setTime(getDate(false));
			
			deploymentMap.put(deploymentID, status);
			
			InstallApplicationRequest appRequest = new InstallApplicationRequest();

			appRequest.setApplicationName(appName);
			appRequest.setApplcationFileUploadKey(applicationFileUploadKey);

			if (isDeploy) restInstallApplication(appRequest, deploymentID);
			
			debugMsg += "Request has been processed sucessfully (DeploymentID= " + deploymentID + ").";
		} catch (RestErrorException e) {
			debugMsg += e.getMessage();
		}

		// creating response
		final ConfigApplicationResponse response = new ConfigApplicationResponse();
		response.setAppName(appName);
		response.setAdminPassword(adminPassword);
		response.setRootPassword(rootPassword);
		response.setHostName(hostName);
		response.setDomainName(domainName);
		response.setDeviceName(deviceName);

		response.setGreenZoneIpAddress(greenZoneIpAddress);
		response.setGreenZoneBroadcast(greenZoneBroadcast);
		response.setGreenZoneNetwork(greenZoneNetwork);
		response.setGreenZoneNetmask(greenZoneNetmask);
		response.setGreenZoneInterface(greenZoneInterface);

		response.setOrangeZoneIpAddress(orangeZoneIpAddress);
		response.setOrangeZoneBroadcast(orangeZoneBroadcast);
		response.setOrangeZoneNetwork(orangeZoneNetwork);
		response.setOrangeZoneNetmask(orangeZoneNetmask);
		response.setOrangeZoneInterface(orangeZoneInterface);

		response.setRedZoneIpAddress(redZoneIpAddress);
		response.setRedZoneBroadcast(redZoneBroadcast);
		response.setRedZoneNetwork(redZoneNetwork);
		response.setRedZoneNetmask(redZoneNetmask);
		response.setRedZoneInterface(redZoneInterface);
		
		response.setDeploymentID(deploymentID);
		
		response.setMessage(debugMsg);
		
		// set utm deployment status 1 (VM creation request has been sent)
//		 tmpDeploymentStatus = 1;

		return response;
	}

	private String getStatusMessage(int status) {
		String message = "";

		switch (status) {
		case 0:
			message = "Appliance Manager로 연결을 준비 중입니다.";
			message = "Prepare connection to the Appliance Manager.";
			break;
		case 1:
			message = "Appliance VM 생성을 요청하였습니다.";
			message = "Send request to create an appliance VM.";
			break;
		case 2:
			message = "Appliance VM 생성 완료되었습니다.";
			message = "The appliance VM has been successfully created.";
			break;
		case 3:
			message = "Appliance VM과 연결을 확인합니다.";
			message = "Try to connect to the Appliance VM";
			break;
		case 4:
			message = "Appliance VM과 연결되었습니다.";
			message = "Successfully connected to the Appliance VM.";
			break;
		case 5:
			message = "Appliance 설정을 요청하였습니다.";
			message = "Request to configure the Appliance.";
			break;
		case 6:
			message = "Appliance 설정을 완료하였습니다.";
			message = "Appliance configuration has successfully completed.";
			break;
		case 7:
			message = "구성이 완료되었습니다.";
			message = "Completed!!!";
			break;
		default:
			message = "잘못된 상태값 입니다.(" + Integer.toString(status) + ")";
			message = "Invalid Status (" + Integer.toString(status) + ")";
		}

		return message;
	}
	
	// ngkim: getDate - return current date info including seconds
	private String getDate(boolean wait) {
		SimpleDateFormat dateFormat = new SimpleDateFormat(
				"yyyy-MM-dd HH:mm:ss");

		Date now = new Date();
		if (lastDate == null) lastDate = now; // initialization		
		if (tmpDeploymentStatus == 0) tmpDeploymentStatus = 1;
		
		if (wait) { // real wait
			int nextStatus = (tmpDeploymentStatus < tmpTotalDeploymentStep) ? (tmpDeploymentStatus + 1):1;
			if( (now.getTime() - lastDate.getTime()) >= delayPerStep[tmpDeploymentStatus] * 1000) {
				lastDate = now;
				tmpDeploymentStatus = nextStatus;
			} 
		} else { // just print wait time
			if( tmpDeploymentStatus == 1) {
				lastDate = now;
			} else 
				lastDate = new Date(lastDate.getTime() + delayPerStep[tmpDeploymentStatus-1] * 1000);			
		}
		
		return dateFormat.format(lastDate);
	}

	@RequestMapping(value = "/{deploymentId}/status", method = RequestMethod.GET)
	public DeploymentStatus getApplicationStatusByDeploymentId(
			@PathVariable final String deploymentId)
			throws ResourceNotFoundException, RestErrorException {

		if (deploymentId == null) {
			throw new RestErrorException(
					CloudifyErrorMessages.MISSING_DEPLOYMENT_ID.getName(),
					"getApplicationStatusByDeploymentId");
		}

		/* TODO: ngkim, enable verifyDeploymentIdExists */
		// verifyDeploymentIdExists(deploymentId);

		DeploymentStatus status = (DeploymentStatus)deploymentMap.get(deploymentId);
		
		int totalStep = Integer.parseInt(status.getTotalSteps());
		int curStep = Integer.parseInt(status.getCurrentStep());

		int newStep = (curStep < totalStep) ? (curStep + 1):1;		
		
		status.setCurrentStep(new String(Integer.toString(newStep)));
		status.setStatus("OK");
		status.setMessage(getStatusMessage(newStep));
		status.setTime(getDate(false));
		
		// update deployment status
		deploymentMap.put(deploymentId, status);

		return status;
	}
	
	private String setMgmtUrl(String serviceName) {
		String mgmtUrl = "";
		
		// set mgmtUrl for each serviceName
		if(serviceName.trim().equals("firewall")) {
			mgmtUrl = "https://221.145.180.73:10443/manage/dashboard";			
		} else if (serviceName.trim().equals("vpn")) {
			mgmtUrl = "https://221.145.180.73:10443/manage/dashboard";
		} else if (serviceName.trim().equals("ips")) {
			mgmtUrl = "http://221.145.180.72";
		} else if (serviceName.trim().equals("voip")) {
			mgmtUrl = "telnet://221.145.180.85";
		} else {
			mgmtUrl = "https://221.145.180.73:10443/manage/dashboard";	
		}
		
		return mgmtUrl;		
	}
	
	private String getMgmtUrl(String serviceName) {
		String mgmtUrl = "";
		BufferedReader br = null;

		// generate fileName by concatenating serviceName with '.mgmt.url'
		String mgmtUrlFile = serviceName + ".mgmt.url";
		
		try {
			File file = new File(mgmtUrlFile);

			if (file.createNewFile()) {
				// If there's no mgmt.url, create it with default url info.
				mgmtUrl = setMgmtUrl(serviceName);
				
				// true = append file
				FileWriter fileWritter = new FileWriter(file.getName(), true);
				BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
				bufferWritter.write(mgmtUrl);
				bufferWritter.close();
			} else {
				// If there's mgmt.url, read url from it.
				br = new BufferedReader(new FileReader(file.getName()));

				String tmpLine = "";
				while ((tmpLine = br.readLine()) != null) {
					mgmtUrl = tmpLine;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)
					br.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}

		return mgmtUrl;
	}

	@RequestMapping(value = "/{deploymentId}/services/{serviceName}/mgmtUrl", method = RequestMethod.GET)
	public DeploymentResult getManagementUrlByDeploymentId(
			@PathVariable final String deploymentId,
			@PathVariable final String serviceName)
			throws ResourceNotFoundException, RestErrorException {

		if (deploymentId == null) {
			throw new RestErrorException(
					CloudifyErrorMessages.MISSING_DEPLOYMENT_ID.getName(),
					"getApplicationStatusByDeploymentId");
		}

		/* TODO: ngkim, enable verifyDeploymentIdExists */

		// verifyDeploymentIdExists(deploymentId);

		DeploymentResult result = new DeploymentResult();

		String mgmtUrl = getMgmtUrl(serviceName);

		result.setMgmtUrl(mgmtUrl);

		return result;
	}

	private boolean waitForPu(final String applicationName,
			final String serviceName, final long timeout,
			final TimeUnit timeUnit) {

		final String absolutePuName = ServiceUtils.getAbsolutePUName(
				applicationName, serviceName);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine("[waitForPu] waiting for processing unit with name "
					+ absolutePuName + " to be created.");
		}
		return admin.getProcessingUnits().waitFor(absolutePuName, timeout,
				timeUnit) != null;
	}

	private void validateInstallApplication(final Application application,
			final InstallApplicationRequest request,
			final File applicationOverridesFile) throws RestErrorException {

		// get cloud overrides file
		final File cloudOverridesFile = getFromRepo(
				request.getCloudOverridesUploadKey(),
				CloudifyMessageKeys.WRONG_CLOUD_OVERRIDES_UPLOAD_KEY.getName(),
				application.getName());

		// get cloud configuration file and content
		final File cloudConfigurationFile = getFromRepo(
				request.getCloudConfigurationUploadKey(),
				CloudifyMessageKeys.WRONG_CLOUD_CONFIGURATION_UPLOAD_KEY
						.getName(), application.getName());

		// create validation context
		final InstallApplicationValidationContext validationContext = new InstallApplicationValidationContext();
		validationContext.setApplication(application);
		validationContext.setCloud(restConfig.getCloud());
		validationContext.setAdmin(admin);
		validationContext.setApplicationOverridesFile(applicationOverridesFile);
		validationContext.setCloudConfigurationFile(cloudConfigurationFile);
		validationContext.setCloudOverridesFile(cloudOverridesFile);
		validationContext.setDebugMode(request.getDebugMode());
		validationContext.setDebugEvents(request.getDebugEvents());
		validationContext.setDebugAll(request.isDebugAll());

		// call validate for each install application validator.
		for (final InstallApplicationValidator validator : installApplicationValidators) {
			validator.validate(validationContext);
		}
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @return {@link org.cloudifysource.dsl.rest.response.ApplicationDescription}
	 *         .
	 * @throws ResourceNotFoundException .
	 */
	@RequestMapping(value = "/applications/{appName}/description", method = RequestMethod.GET)
	public ApplicationDescription getApplicationDescription(
			@PathVariable final String appName)
			throws ResourceNotFoundException {
		final ApplicationDescriptionFactory appDescriptionFactory = new ApplicationDescriptionFactory(
				restConfig.getAdmin());

		// Check that Application exists
		final org.openspaces.admin.application.Application app = this.restConfig
				.getAdmin().getApplications()
				.waitFor(appName, 10, TimeUnit.SECONDS);
		if (app == null) {
			throw new ResourceNotFoundException(appName);
		}

		// if security is turned on - verify the current user is allowed to view
		// this application
		if (permissionEvaluator != null) {
			final ProcessingUnit[] pus = app.getProcessingUnits()
					.getProcessingUnits();
			if (pus.length > 0) {
				final Authentication authentication = SecurityContextHolder
						.getContext().getAuthentication();
				final CloudifyAuthorizationDetails authDetails = new CloudifyAuthorizationDetails(
						authentication);
				// all the application PUs are supposed to have the same
				// auth-groups setting so we use the first.
				final String puAuthGroups = pus[0]
						.getBeanLevelProperties()
						.getContextProperties()
						.getProperty(
								CloudifyConstants.CONTEXT_PROPERTY_AUTH_GROUPS);
				try {
					permissionEvaluator.verifyPermission(authDetails,
							puAuthGroups, "view");
				} catch (AccessDeniedException e) {
					// since this is request to "view" an object, access denied
					// should appear as "resource not found"
					throw new ResourceNotFoundException(appName);
				}
			}
		}

		return appDescriptionFactory.getApplicationDescription(appName);
	}

	/**
	 * @return List of
	 *         {@link org.cloudifysource.dsl.rest.response.ApplicationDescription}
	 *         objects.
	 */
	@RequestMapping(value = "/applications/description", method = RequestMethod.GET)
	@PostFilter("hasPermission(filterObject, 'view')")
	public List<ApplicationDescription> getApplicationDescriptions() {
		final ApplicationDescriptionFactory appDescriptionFactory = new ApplicationDescriptionFactory(
				restConfig.getAdmin());

		return appDescriptionFactory.getApplicationDescriptions();
	}

	private List<ProcessingUnit> createUninstallOrder(
			final ProcessingUnit[] pus, final String applicationName) {

		// TODO: Refactor this - merge with createServiceOrder, as methods are
		// very similar
		final DirectedGraph<ProcessingUnit, DefaultEdge> graph = new DefaultDirectedGraph<ProcessingUnit, DefaultEdge>(
				DefaultEdge.class);

		for (final ProcessingUnit processingUnit : pus) {
			graph.addVertex(processingUnit);
		}

		final Map<String, ProcessingUnit> puByName = new HashMap<String, ProcessingUnit>();
		for (final ProcessingUnit processingUnit : pus) {
			puByName.put(processingUnit.getName(), processingUnit);
		}

		for (final ProcessingUnit processingUnit : pus) {
			final String dependsOn = (String) processingUnit
					.getBeanLevelProperties().getContextProperties()
					.get(CloudifyConstants.CONTEXT_PROPERTY_DEPENDS_ON);
			if (dependsOn == null) {
				logger.warning("Could not find the "
						+ CloudifyConstants.CONTEXT_PROPERTY_DEPENDS_ON
						+ " property for processing unit "
						+ processingUnit.getName());

			} else {
				final String[] dependencies = dependsOn.replace("[", "")
						.replace("]", "").split(",");
				for (final String puName : dependencies) {
					final String normalizedPuName = puName.trim();
					if (normalizedPuName.length() > 0) {
						final ProcessingUnit dependency = puByName
								.get(normalizedPuName);
						if (dependency == null) {
							logger.severe("Could not find Processing Unit "
									+ normalizedPuName
									+ " that Processing Unit "
									+ processingUnit.getName() + " depends on");
						} else {
							// the reverse to the install order.
							graph.addEdge(processingUnit, dependency);
						}
					}
				}
			}
		}

		final CycleDetector<ProcessingUnit, DefaultEdge> cycleDetector = new CycleDetector<ProcessingUnit, DefaultEdge>(
				graph);
		final boolean containsCycle = cycleDetector.detectCycles();

		if (containsCycle) {
			logger.warning("Detected a cycle in the dependencies of application: "
					+ applicationName
					+ " while preparing to uninstall."
					+ " The service in this application will be uninstalled in a random order");

			return Arrays.asList(pus);
		}

		final TopologicalOrderIterator<ProcessingUnit, DefaultEdge> iterator = new TopologicalOrderIterator<ProcessingUnit, DefaultEdge>(
				graph);

		final List<ProcessingUnit> orderedList = new ArrayList<ProcessingUnit>();
		while (iterator.hasNext()) {
			final ProcessingUnit nextPU = iterator.next();
			if (!orderedList.contains(nextPU)) {
				orderedList.add(nextPU);
			}
		}
		// Collections.reverse(orderedList);
		return orderedList;

	}

	private List<Service> createServiceDependencyOrder(
			final org.cloudifysource.domain.Application application) {
		final DirectedGraph<Service, DefaultEdge> graph = new DefaultDirectedGraph<Service, DefaultEdge>(
				DefaultEdge.class);

		final Map<String, Service> servicesByName = new HashMap<String, Service>();

		final List<Service> services = application.getServices();

		for (final Service service : services) {
			// keep a map of names to services
			servicesByName.put(service.getName(), service);
			// and create the graph node
			graph.addVertex(service);
		}

		for (final Service service : services) {
			final List<String> dependsList = service.getDependsOn();
			if (dependsList != null) {
				for (final String depends : dependsList) {
					final Service dependency = servicesByName.get(depends);
					if (dependency == null) {
						throw new IllegalArgumentException("Dependency '"
								+ depends + "' of service: "
								+ service.getName() + " was not found");
					}

					graph.addEdge(dependency, service);
				}
			}
		}

		final CycleDetector<Service, DefaultEdge> cycleDetector = new CycleDetector<Service, DefaultEdge>(
				graph);
		final boolean containsCycle = cycleDetector.detectCycles();

		if (containsCycle) {
			final Set<Service> servicesInCycle = cycleDetector.findCycles();
			final StringBuilder sb = new StringBuilder();
			boolean first = true;
			for (final Service service : servicesInCycle) {
				if (!first) {
					sb.append(",");
				} else {
					first = false;
				}
				sb.append(service.getName());
			}

			final String cycleString = sb.toString();

			// NOTE: This is not exactly how the cycle detector works. The
			// returned list is the vertex set for the subgraph of all cycles.
			// So if there are multiple cycles, the list will contain the
			// members of all of them.
			throw new IllegalArgumentException(
					"The dependency graph of application: "
							+ application.getName()
							+ " contains one or more cycles. "
							+ "The services that form a cycle are part of the following group: "
							+ cycleString);
		}

		final TopologicalOrderIterator<Service, DefaultEdge> iterator = new TopologicalOrderIterator<Service, DefaultEdge>(
				graph);

		final List<Service> orderedList = new ArrayList<Service>();
		while (iterator.hasNext()) {
			orderedList.add(iterator.next());
		}
		return orderedList;

	}

	/**
	 * Executes an install service request onto the grid. This method is not
	 * synchronous, it does not wait for the installation to complete.
	 * 
	 * @param appName
	 *            The application name this service belongs to.
	 * @param serviceName
	 *            The service name.
	 * @param request
	 *            Request body, specifying all the needed parameters for the
	 *            service.
	 * @return An instance of {@link InstallServiceResponse} containing a
	 *         deployment id, with which you can query for installation events
	 *         and status.
	 * @throws RestErrorException
	 *             Thrown in case an error happened before installation begins.
	 */
	@RequestMapping(value = "/{appName}/services/{serviceName}", method = RequestMethod.POST)
	@PreAuthorize("isFullyAuthenticated() and hasPermission(#request.getAuthGroups(), 'deploy')")
	public InstallServiceResponse installService(
			@PathVariable final String appName,
			@PathVariable final String serviceName,
			@RequestBody final InstallServiceRequest request)
			throws RestErrorException {

		logger.info("[installService] - installing service " + serviceName);
		final String absolutePuName = ServiceUtils.getAbsolutePUName(appName,
				serviceName);

		// validate upload key
		String uploadKey = request.getServiceFolderUploadKey();
		if (StringUtils.isBlank(uploadKey)) {
			throw new RestErrorException(
					CloudifyErrorMessages.UPLOAD_KEY_PARAMETER_MISSING
							.getName());
		}

		// get service packed folder
		final File servicePackedFolder = getFromRepo(uploadKey,
				CloudifyMessageKeys.WRONG_SERVICE_FOLDER_UPLOAD_KEY.getName(),
				absolutePuName);

		// extract the service folder and working directory
		File serviceDir;
		try {
			serviceDir = ServiceReader.extractProjectFileToDir(
					servicePackedFolder, absolutePuName, extractedFodler);
		} catch (final IOException e) {
			logger.log(Level.WARNING, "Failed to extract project file ["
					+ servicePackedFolder.getAbsolutePath()
					+ "] to new directory " + absolutePuName + " [under "
					+ extractedFodler.getAbsolutePath() + "]", e);
			throw new RestErrorException(
					CloudifyMessageKeys.FAILED_TO_EXTRACT_PROJECT_FILE
							.getName(),
					absolutePuName);
		}

		// get overrides file
		final File serviceOverridesFile = getFromRepo(
				request.getServiceOverridesUploadKey(),
				CloudifyMessageKeys.WRONG_SERVICE_OVERRIDES_UPLOAD_KEY
						.getName(), absolutePuName);

		// read the service
		File workingProjectDir = new File(serviceDir, "ext");
		final DSLServiceCompilationResult readServiceResult = readService(
				workingProjectDir, request.getServiceFileName(),
				absolutePuName, null, serviceOverridesFile);
		Service service = readServiceResult.getService();

		// perform validations
		logger.finest("[installService] - performing validations for service "
				+ serviceName);
		File overridesFile = readServiceResult.getServiceOverridesFile();
		validateInstallService(request, service, absolutePuName, overridesFile);

		// merge properties with overrides files
		File propertiesFile = readServiceResult.getServicePropertiesFile();
		if (propertiesFile == null) {
			propertiesFile = DSLUtils.getPropertiesFile(workingProjectDir);
		}

		PropertiesOverridesMerger merger = new PropertiesOverridesMerger(
				propertiesFile, null /* application properties file */,
				propertiesFile, overridesFile);
		merger.merge();

		File updatedPackedFile = servicePackedFolder;
		if (merger.isMerged()) {
			// re-pack the service folder after merge
			try {
				logger.finest("[installService] - re-pack directory with the updated properties file after merge.");
				updatedPackedFile = Packager.createZipFile(absolutePuName,
						serviceDir);
			} catch (IOException e) {
				logger.log(
						Level.WARNING,
						"Failed to re-pack service folder ["
								+ serviceDir.getAbsolutePath() + "]. Reason: "
								+ e.getMessage());
				throw new RestErrorException(
						CloudifyErrorMessages.FAILED_PACKING_SERVICE_FOLDER
								.getName(),
						serviceDir);
			}
		}

		// set the new authentication groups
		String effectiveAuthGroups = getEffectiveAuthGroups(request
				.getAuthGroups());
		request.setAuthGroups(effectiveAuthGroups);

		// install the service
		final String deploymentID = UUID.randomUUID().toString();
		return installServiceInternal(appName, serviceName, request,
				deploymentID, null, service, updatedPackedFile);
	}

	/**
	 * An internal implementation for installing a service.
	 * 
	 * @param appName
	 *            Application name.
	 * @param serviceName
	 *            Service name.
	 * @param request
	 *            Install service request.
	 * @param deploymentID
	 *            the application deployment ID.
	 * @param serviceProps
	 *            service properties dependent on the application.
	 * @param service
	 *            the service object.
	 * @param packedFile
	 *            the service packed file.
	 * @return an install service response.
	 * @throws RestErrorException .
	 */
	public InstallServiceResponse installServiceInternal(final String appName,
			final String serviceName, final InstallServiceRequest request,
			final String deploymentID,
			final ServiceApplicationDependentProperties serviceProps,
			final Service service, final File packedFile)
			throws RestErrorException {

		final String absolutePuName = ServiceUtils.getAbsolutePUName(appName,
				serviceName);

		// update template name
		final String templateName = getTempalteNameFromService(service);

		// get cloud overrides file
		final File cloudOverridesFile = getFromRepo(
				request.getCloudOverridesUploadKey(),
				CloudifyMessageKeys.WRONG_CLOUD_OVERRIDES_UPLOAD_KEY.getName(),
				absolutePuName);

		// get cloud configuration file and content
		final File cloudConfigurationFile = getFromRepo(
				request.getCloudConfigurationUploadKey(),
				CloudifyMessageKeys.WRONG_CLOUD_CONFIGURATION_UPLOAD_KEY
						.getName(), absolutePuName);

		final byte[] cloudConfigurationContents = getCloudConfigurationContent(
				cloudConfigurationFile, absolutePuName);

		// update effective authGroups
		String effectiveAuthGroups = getEffectiveAuthGroups(request
				.getAuthGroups());
		request.setAuthGroups(effectiveAuthGroups);

		String cloudOverrides = null;
		try {
			if (cloudOverridesFile != null) {
				cloudOverrides = FileUtils.readFileToString(cloudOverridesFile);
			}
		} catch (IOException e) {
			throw new RestErrorException(
					"Failed reading cloud overrides file.", e);
		}

		// remove any leftover service attributes.
		deleteServiceAttributes(appName, serviceName);

		// deploy
		final DeploymentConfig deployConfig = new DeploymentConfig();
		final String locators = extractLocators(restConfig.getAdmin());
		final Cloud cloud = restConfig.getCloud();
		deployConfig.setCloudConfig(cloudConfigurationContents);
		deployConfig.setDeploymentId(deploymentID);
		deployConfig.setAuthGroups(effectiveAuthGroups);
		deployConfig.setAbsolutePUName(absolutePuName);
		deployConfig.setCloudOverrides(cloudOverrides);
		deployConfig.setCloud(cloud);
		deployConfig.setPackedFile(packedFile);
		deployConfig.setTemplateName(templateName);
		deployConfig.setApplicationName(appName);
		deployConfig.setInstallRequest(request);
		deployConfig.setLocators(locators);
		deployConfig.setService(service);

		// create elastic deployment object.
		final ElasticProcessingUnitDeploymentFactory fac = new ElasticProcessingUnitDeploymentFactoryImpl(
				this.restConfig);
		final ElasticDeploymentTopology deployment;
		try {
			deployment = fac.create(deployConfig);
		} catch (ElasticDeploymentCreationException e) {
			throw new RestErrorException("Failed creating deployment object.",
					e);
		}

		try {
			ProcessingUnit processingUnit = deployAndWait(serviceName,
					deployment);

			// save a reference to the processing unit in the events cache.
			// this is for easy container discovery during events polling from
			// clients.
			populateEventsCache(deploymentID, processingUnit);
		} catch (final TimeoutException e) {
			throw new RestErrorException("Timed out waiting for deployment.", e);
		}

		final InstallServiceResponse installServiceResponse = new InstallServiceResponse();
		installServiceResponse.setDeploymentID(deploymentID);
		return installServiceResponse;
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param serviceName
	 *            .
	 * @return .
	 * @throws ResourceNotFoundException .
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/description", method = RequestMethod.GET)
	public ServiceDescription getServiceDescription(
			@PathVariable final String appName,
			@PathVariable final String serviceName)
			throws ResourceNotFoundException {

		final ApplicationDescriptionFactory appDescriptionFactory = new ApplicationDescriptionFactory(
				restConfig.getAdmin());

		return appDescriptionFactory.getServiceDescription(ServiceUtils
				.getAbsolutePUName(appName, serviceName));
	}

	/**
	 * Retrieves a list of service descriptions belonging to a specific
	 * deployment.
	 * 
	 * @param deploymentId
	 *            The deployment id.
	 * @return The services description.
	 * @throws RestErrorException
	 *             If the deployment id is null.
	 * @throws ResourceNotFoundException .
	 */
	@RequestMapping(value = "/{deploymentId}/description", method = RequestMethod.GET)
	public List<ServiceDescription> getServiceDescriptionListByDeploymentId(
			@PathVariable final String deploymentId)
			throws ResourceNotFoundException, RestErrorException {

		if (deploymentId == null) {
			throw new RestErrorException(
					CloudifyErrorMessages.MISSING_DEPLOYMENT_ID.getName(),
					"getServiceDescriptionListByDeploymentId");
		}
		verifyDeploymentIdExists(deploymentId);

		final ApplicationDescriptionFactory appDescriptionFactory = new ApplicationDescriptionFactory(
				restConfig.getAdmin());
		List<ServiceDescription> descriptions = new ArrayList<ServiceDescription>();
		EventsCacheValue value = eventsCache.getIfExists(new EventsCacheKey(
				deploymentId));
		if (value != null) {
			for (ProcessingUnit pu : value.getProcessingUnits()) {
				ServiceDescription serviceDescription = appDescriptionFactory
						.getServiceDescription(pu);
				if (!serviceDescription.getInstancesDescription().isEmpty()) {
					descriptions.add(serviceDescription);
				} else {
					// pu is stale. no instances
				}
			}
		}
		return descriptions;
	}

	/**
	 * 
	 * @param appName
	 *            The application name.
	 * @param timeoutInMinutes
	 *            The timeout in minutes.
	 * @return uninstall response.
	 * @throws RestErrorException .
	 */
	@RequestMapping(value = "/{appName}", method = RequestMethod.DELETE)
	@PreAuthorize("isFullyAuthenticated()")
	public UninstallApplicationResponse uninstallApplication(
			@PathVariable final String appName,
			@RequestParam(required = false, defaultValue = "15") final Integer timeoutInMinutes)
			throws RestErrorException {

		validateUninstallApplication(appName);

		final Authentication authentication = SecurityContextHolder
				.getContext().getAuthentication();
		// Check that Application exists
		final org.openspaces.admin.application.Application app = this.restConfig
				.getAdmin().getApplications()
				.waitFor(appName, 10, TimeUnit.SECONDS);

		final ProcessingUnit[] pus = app.getProcessingUnits()
				.getProcessingUnits();

		if (pus.length > 0) {
			if (permissionEvaluator != null) {
				final CloudifyAuthorizationDetails authDetails = new CloudifyAuthorizationDetails(
						authentication);
				// all the application PUs are supposed to have the same
				// auth-groups setting
				final String puAuthGroups = pus[0]
						.getBeanLevelProperties()
						.getContextProperties()
						.getProperty(
								CloudifyConstants.CONTEXT_PROPERTY_AUTH_GROUPS);
				permissionEvaluator.verifyPermission(authDetails, puAuthGroups,
						"deploy");
			}
		}

		final StringBuilder sb = new StringBuilder();
		final List<ProcessingUnit> uninstallOrder = createUninstallOrder(pus,
				appName);
		final String deploymentId = uninstallOrder.get(0)
				.getBeanLevelProperties().getContextProperties()
				.getProperty(CloudifyConstants.CONTEXT_PROPERTY_DEPLOYMENT_ID);

		logger.info("Uninstalling application " + appName
				+ " . DeploymentId is " + deploymentId);
		logger.fine("Uninstall order is " + orderToNames(uninstallOrder));

		FutureTask<Boolean> undeployTask;
		logger.log(Level.INFO, "Starting to poll for" + appName
				+ " uninstall lifecycle events.");
		if (uninstallOrder.size() > 0) {

			undeployTask = new FutureTask<Boolean>(new Runnable() {
				private final long startTime = System.currentTimeMillis();

				@Override
				public void run() {
					final List<String> failedTasks = new ArrayList<String>();
					for (final ProcessingUnit processingUnit : uninstallOrder) {
						if (permissionEvaluator != null) {
							final CloudifyAuthorizationDetails authDetails = new CloudifyAuthorizationDetails(
									authentication);
							final String puAuthGroups = processingUnit
									.getBeanLevelProperties()
									.getContextProperties()
									.getProperty(
											CloudifyConstants.CONTEXT_PROPERTY_AUTH_GROUPS);
							permissionEvaluator.verifyPermission(authDetails,
									puAuthGroups, "deploy");
						}

						final long undeployTimeout = startTime
								+ TimeUnit.MINUTES.toMillis(timeoutInMinutes)
								- System.currentTimeMillis();
						try {
							if (processingUnit.waitForManaged(
									WAIT_FOR_MANAGED_TIMEOUT_SECONDS,
									TimeUnit.SECONDS) == null) {
								logger.log(Level.WARNING,
										"Failed to locate GSM that is managing Processing Unit "
												+ processingUnit.getName());
							} else {
								logger.log(Level.INFO,
										"Undeploying Processing Unit "
												+ processingUnit.getName()
												+ " . Timeout is "
												+ undeployTimeout);
								populateEventsCache(deploymentId,
										processingUnit);
								boolean undeployed = processingUnit
										.undeployAndWait(undeployTimeout,
												TimeUnit.MILLISECONDS);
								if (!undeployed) {
									logger.warning("Failed to undeploy processing unit: "
											+ processingUnit.getName());
									failedTasks.add(ServiceUtils
											.getApplicationServiceName(
													processingUnit.getName(),
													appName));
								}
								logger.log(Level.INFO, "Processing Unit "
										+ processingUnit.getName() + " was "
										+ "undeployed successfully");
								final String serviceName = ServiceUtils
										.getApplicationServiceName(
												processingUnit.getName(),
												appName);
								logger.info("Removing application service scope attributes for service "
										+ serviceName);
								deleteServiceAttributes(appName, serviceName);
							}
						} catch (final Exception e) {
							failedTasks.add(ServiceUtils
									.getApplicationServiceName(
											processingUnit.getName(), appName));
							final String msg = "Failed to undeploy processing unit: "
									+ processingUnit.getName()
									+ " while uninstalling application "
									+ appName
									+ ". Uninstall will continue, but service "
									+ processingUnit.getName()
									+ " may remain in an unstable state";

							logger.log(Level.SEVERE, msg, e);
						}
					}
					if (failedTasks.isEmpty()) {
						DeploymentEvent undeployFinishedEvent = new DeploymentEvent();
						undeployFinishedEvent
								.setDescription(CloudifyConstants.UNDEPLOYED_SUCCESSFULLY_EVENT);
						eventsCache.add(new EventsCacheKey(deploymentId),
								undeployFinishedEvent);
						logger.log(Level.INFO, "Application " + appName
								+ " uninstalled successfully");
					} else {
						for (String serviceName : failedTasks) {
							DeploymentEvent failureEvent = new DeploymentEvent();
							failureEvent
									.setDescription(MessageFormat
											.format("Service undeployment was interrupted for service: <{0}>",
													serviceName));
							eventsCache.add(new EventsCacheKey(deploymentId),
									failureEvent);
						}
					}
				}
			}, Boolean.TRUE);

			((InternalAdmin) this.restConfig.getAdmin())
					.scheduleAdminOperation(undeployTask);
		}

		final String errors = sb.toString();
		if (errors.length() == 0) {
			logger.info("Removing all application scope attributes for application "
					+ appName);
			deleteApplicationScopeAttributes(appName);
			final UninstallApplicationResponse response = new UninstallApplicationResponse();
			response.setDeploymentID(deploymentId);
			return response;
		}
		throw new RestErrorException(errors);
	}

	private List<String> orderToNames(final List<ProcessingUnit> order) {

		List<String> names = new ArrayList<String>();
		for (ProcessingUnit pu : order) {
			names.add(pu.getName());
		}
		return names;
	}

	private void deleteApplicationScopeAttributes(final String applicationName) {
		final ApplicationCloudifyAttribute applicationAttributeTemplate = new ApplicationCloudifyAttribute(
				applicationName, null, null);
		gigaSpace.takeMultiple(applicationAttributeTemplate);
	}

	private void validateUninstallApplication(final String appName)
			throws RestErrorException {
		final UninstallApplicationValidationContext validationContext = new UninstallApplicationValidationContext();
		validationContext.setCloud(restConfig.getCloud());
		validationContext.setAdmin(admin);
		validationContext.setApplicationName(appName);
		for (final UninstallApplicationValidator validator : uninstallApplicationValidators) {
			validator.validate(validationContext);
		}
	}

	/**
	 * Uninstalls a service.
	 * 
	 * @param appName
	 *            the application name
	 * @param serviceName
	 *            the service name
	 * @param timeoutInMinutes
	 *            timeout in minutes
	 * @return UUID of this action, can be used to follow the relevant events
	 * @throws ResourceNotFoundException
	 *             Indicates the service could not be found
	 * @throws RestErrorException
	 *             Indicates the uninstall operation could not be performed
	 */
	@RequestMapping(value = "/{appName}/services/{serviceName}", method = RequestMethod.DELETE)
	@PreAuthorize("isFullyAuthenticated()")
	public UninstallServiceResponse uninstallService(
			@PathVariable final String appName,
			@PathVariable final String serviceName,
			@RequestParam(required = false, defaultValue = "5") final Integer timeoutInMinutes)
			throws ResourceNotFoundException, RestErrorException {

		// validations
		validateUninstallService(ServiceUtils.getAbsolutePUName(appName,
				serviceName));

		final ProcessingUnit processingUnit = controllerHelper.getService(
				appName, serviceName);
		final String deploymentId = processingUnit.getBeanLevelProperties()
				.getContextProperties()
				.getProperty(CloudifyConstants.CONTEXT_PROPERTY_DEPLOYMENT_ID);

		if (permissionEvaluator != null) {
			final String puAuthGroups = processingUnit
					.getBeanLevelProperties()
					.getContextProperties()
					.getProperty(CloudifyConstants.CONTEXT_PROPERTY_AUTH_GROUPS);
			final Authentication authentication = SecurityContextHolder
					.getContext().getAuthentication();
			final CloudifyAuthorizationDetails authDetails = new CloudifyAuthorizationDetails(
					authentication);
			try {
				permissionEvaluator.verifyPermission(authDetails, puAuthGroups,
						"view");
			} catch (AccessDeniedException e) {
				// if the user is not allowed to view the object, access denied
				// should appear as "resource not found"
				throw new ResourceNotFoundException(appName);
			}

			permissionEvaluator.verifyPermission(authDetails, puAuthGroups,
					"deploy");
		}

		populateEventsCache(deploymentId, processingUnit);

		final FutureTask<Boolean> undeployTask = new FutureTask<Boolean>(
				new Callable<Boolean>() {
					@Override
					public Boolean call() throws Exception {
						boolean result = processingUnit.undeployAndWait(
								timeoutInMinutes, TimeUnit.MINUTES);
						if (!result) { // undeploy was not succesfull
							logger.warning("Failed undeploying processing unit "
									+ processingUnit.getName()
									+ "in "
									+ timeoutInMinutes
									+ " minutes. Please consult the logs.");
						} else { // undeploy was succesfull
							deleteServiceAttributes(appName, serviceName);
							// write to events cache
							DeploymentEvent undeployFinishedEvent = new DeploymentEvent();
							undeployFinishedEvent
									.setDescription(CloudifyConstants.UNDEPLOYED_SUCCESSFULLY_EVENT);
							eventsCache.add(new EventsCacheKey(deploymentId),
									undeployFinishedEvent);
						}
						return result;
					}
				});
		serviceUndeployExecutor.execute(undeployTask);

		final UninstallServiceResponse uninstallServiceResponse = new UninstallServiceResponse();
		uninstallServiceResponse.setDeploymentID(deploymentId);
		return uninstallServiceResponse;
	}

	private void deleteServiceAttributes(final String applicationName,
			final String serviceName) {
		deleteServiceInstanceAttributes(applicationName, serviceName, null);
		final ServiceCloudifyAttribute serviceAttributeTemplate = new ServiceCloudifyAttribute(
				applicationName, serviceName, null, null);
		gigaSpace.takeMultiple(serviceAttributeTemplate);

		// Delete instance attempt data related to this service
		ServiceInstanceAttemptData template = new ServiceInstanceAttemptData();
		template.setApplicationName(applicationName);
		template.setServiceName(serviceName);

		ServiceInstanceAttemptData[] attempts = gigaSpace
				.takeMultiple(template);
		logger.info("Removed " + attempts.length
				+ " instance attempts from management space");

	}

	private void deleteServiceInstanceAttributes(final String applicationName,
			final String serviceName, final Integer instanceId) {
		final InstanceCloudifyAttribute instanceAttributesTemplate = new InstanceCloudifyAttribute(
				applicationName, serviceName, instanceId, null, null);
		gigaSpace.takeMultiple(instanceAttributesTemplate);
	}

	private void validateUninstallService(final String puName)
			throws RestErrorException {
		final UninstallServiceValidationContext validationContext = new UninstallServiceValidationContext();
		validationContext.setCloud(restConfig.getCloud());
		validationContext.setAdmin(admin);
		validationContext.setPuName(puName);

		for (final UninstallServiceValidator validator : uninstallServiceValidators) {
			validator.validate(validationContext);
		}
	}

	private void populateEventsCache(final String deploymentId,
			final ProcessingUnit processingUnit) {
		EventsCacheKey key = new EventsCacheKey(deploymentId);
		EventsCacheValue value = eventsCache.getIfExists(key);
		if (value == null) {
			// first time populating the cache with this deployment id.
			value = new EventsCacheValue();
			value.getProcessingUnits().add(processingUnit);
			eventsCache.put(key, value);
		} else {
			// a value already exists for this deployment id.
			// just add the reference for the current pu.
			logger.fine("Adding processing unit " + processingUnit.getName()
					+ " to events cache value with " + "deployment id "
					+ deploymentId);
			value.getProcessingUnits().add(processingUnit);
		}

		final AdminBasedGridServiceContainerProvider provider = new AdminBasedGridServiceContainerProvider(
				admin);
		// save reference to the containers if exits.
		// will exist only if this is uninstall process.
		Set<GridServiceContainer> containersForDeployment = provider
				.getContainersForDeployment(deploymentId);
		logger.fine("Adding containers " + containersForDeployment
				+ " for events cache key with deployment id " + deploymentId);
		value.getContainers().addAll(containersForDeployment);
	}

	private String getEffectiveAuthGroups(final String authGroups) {
		String effectiveAuthGroups = authGroups;
		if (StringUtils.isBlank(effectiveAuthGroups)) {
			if (permissionEvaluator != null) {
				effectiveAuthGroups = permissionEvaluator
						.getUserAuthGroupsString();
			} else {
				effectiveAuthGroups = "";
			}
		}
		return effectiveAuthGroups;
	}

	private static String extractLocators(final Admin admin) {

		final LookupLocator[] locatorsArray = admin.getLocators();
		final StringBuilder locators = new StringBuilder();

		for (final LookupLocator locator : locatorsArray) {
			locators.append(locator.getHost()).append(':')
					.append(locator.getPort()).append(',');
		}

		if (locators.length() > 0) {
			locators.setLength(locators.length() - 1);
		}

		return locators.toString();
	}

	private ProcessingUnit deployAndWait(final String serviceName,
			final ElasticDeploymentTopology deployment) throws TimeoutException {
		GridServiceManager gsm = getGridServiceManager();
		ProcessingUnit pu = null;

		Integer serviceDiscoveryTimeoutInSeconds = getServiceDiscoveryTimeout();

		if (deployment instanceof ElasticStatelessProcessingUnitDeployment) {
			pu = gsm.deploy(
					(ElasticStatelessProcessingUnitDeployment) deployment,
					serviceDiscoveryTimeoutInSeconds, TimeUnit.SECONDS);
		} else if (deployment instanceof ElasticStatefulProcessingUnitDeployment) {
			pu = gsm.deploy(
					(ElasticStatefulProcessingUnitDeployment) deployment,
					serviceDiscoveryTimeoutInSeconds, TimeUnit.SECONDS);
		} else if (deployment instanceof ElasticSpaceDeployment) {
			pu = gsm.deploy((ElasticSpaceDeployment) deployment,
					serviceDiscoveryTimeoutInSeconds, TimeUnit.SECONDS);
		}
		if (pu == null) {
			throw new TimeoutException("Timed out waiting for Service "
					+ serviceName + " deployment.");
		}
		return pu;
	}

	/**
	 * Gets the service discovery timeout from the cloud configuration. If the
	 * cloud object is null (e.g. localcloud), uses the default timeout (60
	 * seconds)
	 * 
	 * @return service discovery timeout in seconds
	 */
	private Integer getServiceDiscoveryTimeout() {
		Integer serviceDiscoveryTimeoutInSeconds = new Integer(
				CloudifyConstants.DEFAULT_SERVICE_DISCOVERY_TIMEOUT_SEC);
		Cloud cloud = restConfig.getCloud();
		if (cloud != null) {
			serviceDiscoveryTimeoutInSeconds = cloud.getConfiguration()
					.getComponents().getRest()
					.getServiceDiscoveryTimeoutInSeconds();
		}

		logger.finest("serviceDiscoveryTimeoutInSeconds value is set to: "
				+ serviceDiscoveryTimeoutInSeconds);

		return serviceDiscoveryTimeoutInSeconds;
	}

	private GridServiceManager getGridServiceManager() {
		if (restConfig.getAdmin().getGridServiceManagers().isEmpty()) {
			throw new AdminException("Cannot locate Grid Service Manager");
		}
		return restConfig.getAdmin().getGridServiceManagers().iterator().next();
	}

	private DSLServiceCompilationResult readService(
			final File workingProjectDir, final String serviceFileName,
			final String absolutePuName,
			final ServiceApplicationDependentProperties serviceProps,
			final File overridesFile) throws RestErrorException {
		DSLServiceCompilationResult result;
		try {
			if (serviceFileName != null) {
				result = ServiceReader.getServiceFromFile(new File(
						workingProjectDir, serviceFileName), workingProjectDir,
						null /* propertiesFileName */,
						true /* isRunningInGSC */, overridesFile);
			} else {
				result = ServiceReader.getServiceFromDirectory(
						workingProjectDir, overridesFile);
			}
			Service service = result.getService();
			// Setting application dependent properties
			if (serviceProps != null) {
				service.setDependsOn(serviceProps.getDependsOn());
			}
		} catch (final Exception e) {
			throw new RestErrorException(
					CloudifyMessageKeys.FAILED_TO_READ_SERVICE.getName(),
					absolutePuName);
		}
		return result;
	}

	private byte[] getCloudConfigurationContent(
			final File serviceCloudConfigurationFile,
			final String absolutePuName) throws RestErrorException {
		byte[] serviceCloudConfigurationContents = null;
		if (serviceCloudConfigurationFile != null) {
			try {
				serviceCloudConfigurationContents = FileUtils
						.readFileToByteArray(serviceCloudConfigurationFile);
			} catch (final IOException e) {
				throw new RestErrorException(
						CloudifyMessageKeys.FAILED_TO_READ_SERVICE_CLOUD_CONFIGURATION
								.getName(), absolutePuName);
			}
		}
		return serviceCloudConfigurationContents;
	}

	private String getTempalteNameFromService(final Service service) {

		final Cloud cloud = restConfig.getCloud();
		if (cloud == null) {
			return null;
		}

		final ComputeDetails compute = service.getCompute();
		String templateName = restConfig.getDefaultTemplateName();
		if (compute != null) {
			templateName = compute.getTemplate();
		}
		if (IsolationUtils.isGlobal(service)
				&& IsolationUtils.isUseManagement(service)) {
			final String managementTemplateName = cloud.getConfiguration()
					.getManagementMachineTemplate();
			if (compute != null) {
				if (!StringUtils.isBlank(templateName)) {
					if (!templateName.equals(managementTemplateName)) {
						// this is just a clarification log.
						// the service wont be installed on a management
						// machine(even if there is enough memory)
						// because the management machine template does not
						// match the desired template
						logger.warning("Installation of service "
								+ service.getName()
								+ " on a management machine "
								+ "will not be attempted since the specified template("
								+ templateName
								+ ")"
								+ " is different than the management machine template("
								+ managementTemplateName + ")");
					}
				}
			} else {
				templateName = restConfig.getManagementTemplateName();
			}
		}
		return templateName;
	}

	private File getFromRepo(final String uploadKey, final String errorDesc,
			final String absolutePuName) throws RestErrorException {
		if (StringUtils.isBlank(uploadKey)) {
			return null;
		}
		final File file = repo.get(uploadKey);
		if (file == null) {
			throw new RestErrorException(errorDesc, absolutePuName);
		}
		return file;
	}

	private void validateInstallService(final InstallServiceRequest request,
			final Service service, final String absolutePuName,
			final File serviceOverridesFile) throws RestErrorException {

		// get cloud overrides file
		final File cloudOverridesFile = getFromRepo(
				request.getCloudOverridesUploadKey(),
				CloudifyMessageKeys.WRONG_CLOUD_OVERRIDES_UPLOAD_KEY.getName(),
				absolutePuName);

		// get cloud configuration file and content
		final File cloudConfigurationFile = getFromRepo(
				request.getCloudConfigurationUploadKey(),
				CloudifyMessageKeys.WRONG_CLOUD_CONFIGURATION_UPLOAD_KEY
						.getName(), absolutePuName);

		// create validation context
		final InstallServiceValidationContext validationContext = new InstallServiceValidationContext();
		validationContext.setCloud(restConfig.getCloud());
		validationContext.setAdmin(admin);
		validationContext.setService(service);
		validationContext.setCloudOverridesFile(cloudOverridesFile);
		validationContext.setServiceOverridesFile(serviceOverridesFile);
		validationContext.setCloudConfigurationFile(cloudConfigurationFile);
		validationContext.setPuName(absolutePuName);

		// call validate for each install service validator.
		for (final InstallServiceValidator validator : installServiceValidators) {
			validator.validate(validationContext);
		}
	}

	/**
	 * 
	 * @param appName
	 *            .
	 */
	@RequestMapping(value = "/{appName}", method = RequestMethod.GET)
	public void getApplicationStatus(@PathVariable final String appName) {
		throw new UnsupportedOperationException("getApplicationStatus");
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param serviceName
	 *            .
	 */
	@RequestMapping(value = "/{appName}/services/{serviceName}", method = RequestMethod.GET)
	public void getServiceStatus(@PathVariable final String appName,
			@PathVariable final String serviceName) {
		throw new UnsupportedOperationException("getServiceStatus");
	}

	/**
	 * 
	 * @param appName
	 *            .
	 */
	@RequestMapping(value = "/{appName}", method = RequestMethod.PUT)
	public void updateApplication(@PathVariable final String appName) {
		throw new UnsupportedOperationException("updateApplication");
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param serviceName
	 *            .
	 */
	@RequestMapping(value = "/{appName}/services/{serviceName}", method = RequestMethod.PUT)
	public void updateService(@PathVariable final String appName,
			@PathVariable final String serviceName) {
		throw new UnsupportedOperationException("updateService");
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param attributeName
	 *            .
	 * @param updateApplicationAttributeRequest
	 *            .
	 */
	@RequestMapping(value = "/{appName}/attributes/{attributeName}", method = RequestMethod.PUT)
	public void updateApplicationAttribute(
			@PathVariable final String appName,
			@PathVariable final String attributeName,
			@RequestBody final UpdateApplicationAttributeRequest updateApplicationAttributeRequest) {
		throw new UnsupportedOperationException("updateApplicationAttribute");
	}

	/**
	 * Retrieves application level attributes.
	 * 
	 * @param appName
	 *            The application name.
	 * @return An instance of {@link GetApplicationAttributesResponse}
	 *         containing all the application attributes names and values.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the application does not exist.
	 */
	@RequestMapping(value = "/{appName}/attributes", method = RequestMethod.GET)
	public GetApplicationAttributesResponse getApplicationAttributes(
			@PathVariable final String appName)
			throws ResourceNotFoundException {

		// valid application if exist
		controllerHelper.getApplication(appName);

		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to get all attributes of application "
					+ appName);
		}

		// get attributes
		final Map<String, Object> attributes = controllerHelper.getAttributes(
				appName, null, null);

		// create response object
		final GetApplicationAttributesResponse aar = new GetApplicationAttributesResponse();
		// set attributes
		aar.setAttributes(attributes);
		return aar;

	}

	/**
	 * Deletes an application level attribute.
	 * 
	 * @param appName
	 *            The application name.
	 * @param attributeName
	 *            The attribute name.
	 * @return The previous value of the attribute.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the application does not exist.
	 * @throws RestErrorException
	 *             Thrown in case the attribute name is empty.
	 */
	@RequestMapping(value = "/{appName}/attributes/{attributeName}", method = RequestMethod.DELETE)
	public DeleteApplicationAttributeResponse deleteApplicationAttribute(
			@PathVariable final String appName,
			@PathVariable final String attributeName)
			throws ResourceNotFoundException, RestErrorException {

		// valid application if exist
		controllerHelper.getApplication(appName);

		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to delete attributes "
					+ attributeName + " of application " + appName);
		}

		// delete attribute returned previous value
		final Object previousValue = controllerHelper.deleteAttribute(appName,
				null, null, attributeName);

		final DeleteApplicationAttributeResponse daar = new DeleteApplicationAttributeResponse();
		daar.setPreviousValue(previousValue);

		return daar;

	}

	/**
	 * Retrieves service level attributes.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @return An instance of {@link GetServiceAttributesResponse} containing
	 *         all the service attributes names and values.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the service does not exist.
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/attributes", method = RequestMethod.GET)
	public GetServiceAttributesResponse getServiceAttributes(
			@PathVariable final String appName,
			@PathVariable final String serviceName)
			throws ResourceNotFoundException {

		// valid exist service
		controllerHelper.getService(appName, serviceName);

		// logger - request to get all attributes
		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to get all attributes of service "
					+ ServiceUtils.getAbsolutePUName(appName, serviceName)
					+ " of application " + appName);
		}

		// get attributes
		final Map<String, Object> attributes = controllerHelper.getAttributes(
				appName, serviceName, null);

		// create response object
		final GetServiceAttributesResponse sar = new GetServiceAttributesResponse();
		// set attributes
		sar.setAttributes(attributes);
		// return response object
		return sar;

	}

	/**
	 * Sets service level attributes for the given application.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @param request
	 *            Request body, specifying the attributes names and values.
	 * @throws RestErrorException
	 *             Thrown in case the request body is empty.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the service does not exist.
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/attributes", method = RequestMethod.POST)
	public void setServiceAttribute(@PathVariable final String appName,
			@PathVariable final String serviceName,
			@RequestBody final SetServiceAttributesRequest request)
			throws ResourceNotFoundException, RestErrorException {

		// valid service
		controllerHelper.getService(appName, serviceName);

		// validate request object
		if (request == null || request.getAttributes() == null) {
			throw new RestErrorException(
					CloudifyMessageKeys.EMPTY_REQUEST_BODY_ERROR.getName());
		}

		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to set attributes "
					+ request.getAttributes().keySet() + " of service "
					+ ServiceUtils.getAbsolutePUName(appName, serviceName)
					+ " of application " + appName + " to: "
					+ request.getAttributes().values());

		}

		// set attributes
		controllerHelper.setAttributes(appName, serviceName, null,
				request.getAttributes());

	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param serviceName
	 *            .
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/attributes", method = RequestMethod.PUT)
	public void updateServiceAttribute(@PathVariable final String appName,
			@PathVariable final String serviceName) {
		throw new UnsupportedOperationException("updateServiceAttribute");
	}

	/**
	 * Deletes a service level attribute.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @param attributeName
	 *            The attribute name.
	 * @return The previous value of the attribute.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the service does not exist.
	 * @throws RestErrorException
	 *             Thrown in case the attribute name is empty.
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/attributes/{attributeName}", method = RequestMethod.DELETE)
	public DeleteServiceAttributeResponse deleteServiceAttribute(
			@PathVariable final String appName,
			@PathVariable final String serviceName,
			@PathVariable final String attributeName)
			throws ResourceNotFoundException, RestErrorException {

		// valid service
		controllerHelper.getService(appName, serviceName);

		// logger - request to delete attributes
		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to delete attribute "
					+ attributeName + " of service "
					+ ServiceUtils.getAbsolutePUName(appName, serviceName)
					+ " of application " + appName);
		}

		// get delete attribute returned previous value
		final Object previous = controllerHelper.deleteAttribute(appName,
				serviceName, null, attributeName);

		// create response object
		final DeleteServiceAttributeResponse sar = new DeleteServiceAttributeResponse();
		// set previous value
		sar.setPreviousValue(previous);
		// return response object
		return sar;

	}

	/**
	 * Retrieves service instance level attributes.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @param instanceId
	 *            The instance id.
	 * @return An instance of {@link GetServiceInstanceAttributesResponse}
	 *         containing all the service instance attributes names and values.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the service instance does not exist.
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/instances/{instanceId}/attributes", method = RequestMethod.GET)
	public GetServiceInstanceAttributesResponse getServiceInstanceAttributes(
			@PathVariable final String appName,
			@PathVariable final String serviceName,
			@PathVariable final Integer instanceId)
			throws ResourceNotFoundException {

		// valid service
		controllerHelper.getService(appName, serviceName);

		// logger - request to get all attributes
		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to get all attributes of instance number "
					+ instanceId
					+ " of service "
					+ ServiceUtils.getAbsolutePUName(appName, serviceName)
					+ " of application " + appName);
		}

		// get attributes
		final Map<String, Object> attributes = controllerHelper.getAttributes(
				appName, serviceName, instanceId);
		// create response object
		final GetServiceInstanceAttributesResponse siar = new GetServiceInstanceAttributesResponse();
		// set attributes
		siar.setAttributes(attributes);
		// return response object
		return siar;

	}

	/**
	 * Sets service instance level attributes for the given application.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @param instanceId
	 *            The instance id.
	 * @param request
	 *            Request body, specifying the attributes names and values.
	 * @throws RestErrorException
	 *             Thrown in case the request body is empty.
	 * @throws ResourceNotFoundException
	 *             Thrown in case the service instance does not exist.
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/instances/{instanceId}/attributes", method = RequestMethod.POST)
	public void setServiceInstanceAttributes(
			@PathVariable final String appName,
			@PathVariable final String serviceName,
			@PathVariable final Integer instanceId,
			@RequestBody final SetServiceInstanceAttributesRequest request)
			throws ResourceNotFoundException, RestErrorException {

		// valid service
		controllerHelper.getService(appName, serviceName);

		// validate request object
		if (request == null || request.getAttributes() == null) {
			throw new RestErrorException(
					CloudifyMessageKeys.EMPTY_REQUEST_BODY_ERROR.getName());
		}

		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to set attribute "
					+ request.getAttributes().keySet() + " of instance number "
					+ instanceId + " of service "
					+ ServiceUtils.getAbsolutePUName(appName, serviceName)
					+ " of application " + appName + " to: "
					+ request.getAttributes().values());
		}

		// set attributes
		controllerHelper.setAttributes(appName, serviceName, instanceId,
				request.getAttributes());
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param serviceName
	 *            .
	 * @param instanceId
	 *            .
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/instances/{instanceId}/attributes", method = RequestMethod.PUT)
	public void updateServiceInstanceAttribute(
			@PathVariable final String appName,
			@PathVariable final String serviceName,
			@PathVariable final String instanceId) {
		throw new UnsupportedOperationException(
				"updateServiceInstanceAttribute");
	}

	/**
	 * Retrieves USM metric details about the service.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @return Various USM metric details about the service
	 * @throws ResourceNotFoundException .
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/metrics", method = RequestMethod.GET)
	public ServiceMetricsResponse getServiceMetrics(
			@PathVariable final String appName,
			@PathVariable final String serviceName)
			throws ResourceNotFoundException {

		// service instances metrics data
		final List<ServiceInstanceMetricsData> serviceInstanceMetricsDatas = new ArrayList<ServiceInstanceMetricsData>();

		// get service
		final ProcessingUnit service = controllerHelper.getService(appName,
				serviceName);

		// set metrics for every instance
		for (final ProcessingUnitInstance serviceInstance : service
				.getInstances()) {

			final Map<String, Object> metrics = serviceInstance.getStatistics()
					.getMonitors().get("USM").getMonitors();
			serviceInstanceMetricsDatas.add(new ServiceInstanceMetricsData(
					serviceInstance.getInstanceId(), metrics));

		}

		// create response instance
		final ServiceMetricsResponse smr = new ServiceMetricsResponse();
		smr.setAppName(appName);
		smr.setServiceInstaceMetricsData(serviceInstanceMetricsDatas);
		smr.setServiceName(serviceName);

		return smr;

	}

	/**
	 * Retrieves USM metric details about the service instance.
	 * 
	 * @param appName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @param instanceId
	 *            The instance id.
	 * @return Various USM metric details about the service instance.
	 * @throws ResourceNotFoundException .
	 */
	@RequestMapping(value = "{appName}/service/{serviceName}/instances/{instanceId}/metrics", method = RequestMethod.GET)
	public ServiceInstanceMetricsResponse getServiceInstanceMetrics(
			@PathVariable final String appName,
			@PathVariable final String serviceName,
			@PathVariable final Integer instanceId)
			throws ResourceNotFoundException {

		// get service instance
		final ProcessingUnitInstance serviceInstance = controllerHelper
				.getServiceInstance(appName, serviceName, instanceId);

		// get metrics data
		final Map<String, Object> metrics = serviceInstance.getStatistics()
				.getMonitors().get("USM").getMonitors();

		final ServiceInstanceMetricsData serviceInstanceMetricsData = new ServiceInstanceMetricsData(
				instanceId, metrics);

		// create response object
		final ServiceInstanceMetricsResponse simr = new ServiceInstanceMetricsResponse();

		// set response data
		simr.setAppName(appName);
		simr.setServiceName(serviceName);
		simr.setServiceInstanceMetricsData(serviceInstanceMetricsData);

		return simr;
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param serviceName
	 *            .
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/metadata", method = RequestMethod.POST)
	public void setServiceDetails(@PathVariable final String appName,
			@PathVariable final String serviceName) {
		throw new UnsupportedOperationException("setServiceDetails");
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param serviceName
	 *            .
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/metadata", method = RequestMethod.PUT)
	public void updateServiceDetails(@PathVariable final String appName,
			@PathVariable final String serviceName) {
		throw new UnsupportedOperationException("updateServiceDetails");
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param serviceName
	 *            .
	 * @param instanceId
	 *            .
	 */
	@RequestMapping(value = "/{appName}/service/{serviceName}/instances/{instanceId}/metadata", method = RequestMethod.POST)
	public void setServiceInstanceDetails(@PathVariable final String appName,
			@PathVariable final String serviceName,
			@PathVariable final String instanceId) {
		throw new UnsupportedOperationException("setServiceInstanceDetails");
	}

	/**
	 * 
	 * @param appName
	 *            .
	 * @param serviceName
	 *            .
	 */
	@RequestMapping(value = "/appName}/service/{serviceName}/alerts", method = RequestMethod.GET)
	public void getServiceAlerts(@PathVariable final String appName,
			@PathVariable final String serviceName) {
		throw new UnsupportedOperationException("getServiceAlerts");
	}

	public File getExtractedFodler() {
		return this.extractedFodler;
	}

	public RestConfiguration getRestConfig() {
		return restConfig;
	}

	public void setRestConfig(final RestConfiguration restConfig) {
		this.restConfig = restConfig;
	}

	public UploadRepo getRepo() {
		return repo;
	}

	public void setRepo(final UploadRepo repo) {
		this.repo = repo;
	}

	public InstallServiceValidator[] getInstallServiceValidators() {
		return installServiceValidators;
	}

	public void setInstallServiceValidators(
			final InstallServiceValidator[] installServiceValidators) {
		this.installServiceValidators = installServiceValidators;
	}

	public UninstallServiceValidator[] getUninstallServiceValidators() {
		return uninstallServiceValidators;
	}

	public void setUninstallServiceValidators(
			final UninstallServiceValidator[] uninstallServiceValidators) {
		this.uninstallServiceValidators = uninstallServiceValidators;
	}

	public InstallApplicationValidator[] getInstallApplicationValidators() {
		return installApplicationValidators;
	}

	public void setInstallApplicationValidators(
			final InstallApplicationValidator[] installApplicationValidators) {
		this.installApplicationValidators = installApplicationValidators;
	}

	public UninstallApplicationValidator[] getUninstallApplicationValidators() {
		return uninstallApplicationValidators;
	}

	public void setUninstallApplicationValidators(
			final UninstallApplicationValidator[] uninstallApplicationValidators) {
		this.uninstallApplicationValidators = uninstallApplicationValidators;
	}

	public SetServiceInstancesValidator[] getSetServiceInstancesValidators() {
		return setServiceInstancesValidators;
	}

	public void setSetServiceInstancesValidators(
			final SetServiceInstancesValidator[] setServiceInstancesValidators) {
		this.setServiceInstancesValidators = setServiceInstancesValidators;
	}

	/**
	 * Invokes a custom command on all of the specified service instances.
	 * Custom parameters are passed as a map using the POST method and contain
	 * the command name and parameter values for the specified command.
	 * 
	 * @param applicationName
	 *            The application name.
	 * @param serviceName
	 *            The service name.
	 * @param request
	 *            InvokeCustomCommandRequest the request containing the relevant
	 *            parameters.
	 * @return a Map containing the result of each invocation on a service
	 *         instance.
	 * @throws RestErrorException
	 *             When the invocation failed.
	 * @throws ResourceNotFoundException
	 *             When failed to locate service/service instance.
	 */
	@RequestMapping(value = "applications/{applicationName}/services/{serviceName}/invoke", method = RequestMethod.POST)
	@PreAuthorize("isFullyAuthenticated()")
	public InvokeServiceCommandResponse invoke(
			@PathVariable final String applicationName,
			@PathVariable final String serviceName,
			@RequestBody final InvokeCustomCommandRequest request)
			throws RestErrorException, ResourceNotFoundException {

		InvokeServiceCommandResponse response = new InvokeServiceCommandResponse();

		final String absolutePuName = ServiceUtils.getAbsolutePUName(
				applicationName, serviceName);
		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to invoke command of service "
					+ absolutePuName + " of application " + applicationName);
		}

		// Get the PU
		final ProcessingUnit pu = admin.getProcessingUnits().waitFor(
				absolutePuName, PU_DISCOVERY_TIMEOUT_SEC, TimeUnit.SECONDS);
		if (pu == null) {
			// TODO: Consider telling the user he might be using the wrong
			// application name.
			logger.severe("Could not find service " + absolutePuName);
			throw new ResourceNotFoundException(absolutePuName);
		}

		if (permissionEvaluator != null) {
			final String puAuthGroups = pu
					.getBeanLevelProperties()
					.getContextProperties()
					.getProperty(CloudifyConstants.CONTEXT_PROPERTY_AUTH_GROUPS);
			final Authentication authentication = SecurityContextHolder
					.getContext().getAuthentication();
			final CloudifyAuthorizationDetails authDetails = new CloudifyAuthorizationDetails(
					authentication);
			permissionEvaluator.verifyPermission(authDetails, puAuthGroups,
					"deploy");
		}

		// result, mapping service instances to results
		// final Map<String, Object> invocationResult = new HashMap<String,
		// Object>();
		final ProcessingUnitInstance[] instances = pu.getInstances();

		if (instances.length == 0) {
			throw new RestErrorException(
					ResponseConstants.NO_PROCESSING_UNIT_INSTANCES_FOUND_FOR_INVOCATION,
					serviceName);
		}

		// Why a map? TODO: Use an array here instead.
		// map between service name and its future
		final Map<String, Future<Object>> futures = new HashMap<String, Future<Object>>(
				instances.length);
		for (final ProcessingUnitInstance instance : instances) {
			// key includes instance ID and host name
			final String serviceInstanceName = buildServiceInstanceName(instance);
			try {
				Map<String, Object> invocationArgs = preProcessInvocationRequest(
						request.getCommandName(), request.getParameters());
				final Future<Object> future = ((DefaultProcessingUnitInstance) instance)
						.invoke(CloudifyConstants.INVOCATION_PARAMETER_BEAN_NAME_USM,
								invocationArgs);
				futures.put(serviceInstanceName, future);
			} catch (final Exception e) {
				// we log the error message and add it to the response but carry
				// on to the following instances
				String errorMessage = "Error occurred while invoking custom command '"
						+ request.getCommandName()
						+ "' on service "
						+ serviceName
						+ ":"
						+ instance.getInstanceId()
						+ " on host "
						+ instance.getVirtualMachine().getMachine()
								.getHostName()
						+ ". Reported error: "
						+ e.getMessage();
				logger.severe(errorMessage);
				Map<String, String> processedResult = postProcessInvocationResult(
						serviceInstanceName, errorMessage);
				response.setInvocationResult(serviceInstanceName,
						processedResult);
			}
		}

		for (final Map.Entry<String, Future<Object>> entry : futures.entrySet()) {
			String serviceInstanceName = entry.getKey();
			Object invocationResult;

			try {
				invocationResult = entry.getValue().get();
			} catch (final Exception e) {
				// we log the error message and add it to the response but carry
				// on to the following instances
				String errorMessage = "Error occurred while invoking custom command on service "
						+ serviceName
						+ ":"
						+ serviceInstanceName
						+ ". Reported error: " + e.getMessage();
				logger.severe(errorMessage);
				invocationResult = errorMessage;
			}

			// use only tostring of collection values, to avoid serialization
			// problems
			Map<String, String> processedResult = postProcessInvocationResult(
					serviceInstanceName, invocationResult);
			response.setInvocationResult(serviceInstanceName, processedResult);
		}

		return response;
	}

	/**
	 * Invokes a custom command on a specific service instance. Custom
	 * parameters are passed as a map using POST method and contain the command
	 * name and parameter values for the specified command.
	 * 
	 * @param applicationName
	 *            The application name.
	 * @param serviceName
	 *            The service name
	 * @param instanceId
	 *            The service instance number to be invoked.
	 * @param request
	 *            InvokeCustomCommandRequest the request containing the relevant
	 *            parameters.
	 * @return a Map containing the invocation result on the specified instance.
	 * @throws RestErrorException
	 *             When the invocation failed.
	 * @throws ResourceNotFoundException
	 *             When failed to locate service/service instance.
	 */
	@RequestMapping(value = "applications/{applicationName}/services/{serviceName}/instances"
			+ "/{instanceId}/invoke", method = RequestMethod.POST)
	@PreAuthorize("isFullyAuthenticated()")
	public InvokeInstanceCommandResponse invokeInstance(
			@PathVariable final String applicationName,
			@PathVariable final String serviceName,
			@PathVariable final int instanceId,
			@RequestBody final InvokeCustomCommandRequest request)
			throws RestErrorException, ResourceNotFoundException {

		InvokeInstanceCommandResponse response = new InvokeInstanceCommandResponse();
		final String absolutePuName = ServiceUtils.getAbsolutePUName(
				applicationName, serviceName);
		if (logger.isLoggable(Level.FINER)) {
			logger.finer("received request to invoke command of service "
					+ serviceName + " of application " + applicationName);
		}

		// Get PU
		final ProcessingUnit pu = admin.getProcessingUnits().waitFor(
				absolutePuName, PU_DISCOVERY_TIMEOUT_SEC, TimeUnit.SECONDS);

		if (pu == null) {
			// TODO: Consider telling the user he might be using the wrong
			// application name.
			logger.severe("Could not find service " + absolutePuName);
			throw new ResourceNotFoundException(absolutePuName);
		}

		if (permissionEvaluator != null) {
			final String puAuthGroups = pu
					.getBeanLevelProperties()
					.getContextProperties()
					.getProperty(CloudifyConstants.CONTEXT_PROPERTY_AUTH_GROUPS);
			final Authentication authentication = SecurityContextHolder
					.getContext().getAuthentication();
			final CloudifyAuthorizationDetails authDetails = new CloudifyAuthorizationDetails(
					authentication);
			permissionEvaluator.verifyPermission(authDetails, puAuthGroups,
					"deploy");
		}

		final InternalProcessingUnitInstance pui = findInstanceById(pu,
				instanceId);
		if (pui == null) {
			logger.severe("Could not find service instance " + instanceId
					+ " for service " + absolutePuName);
			throw new RestErrorException(
					ResponseConstants.SERVICE_INSTANCE_UNAVAILABLE,
					applicationName, absolutePuName,
					Integer.toString(instanceId));
		}

		final String instanceName = buildServiceInstanceName(pui);

		// Invoke the remote service
		Object invocationResult;
		try {
			Map<String, Object> invocationArgs = preProcessInvocationRequest(
					request.getCommandName(), request.getParameters());
			final Future<?> future = pui.invoke(
					CloudifyConstants.INVOCATION_PARAMETER_BEAN_NAME_USM,
					invocationArgs);
			invocationResult = future.get();
			Map<String, String> finalResult = postProcessInvocationResult(
					instanceName, invocationResult);
			response.setInvocationResult(finalResult);
		} catch (final Exception e) {
			String errorMessage = "Error occurred while invoking custom command on pu instance "
					+ absolutePuName
					+ ":"
					+ instanceId
					+ " on host "
					+ pui.getVirtualMachine().getMachine().getHostName()
					+ ". Reported error: " + e.getMessage();
			logger.severe(errorMessage);
			throw new RestErrorException(
					ResponseConstants.FAILED_TO_INVOKE_INSTANCE,
					absolutePuName, Integer.toString(instanceId),
					e.getMessage());
		}

		return response;
	}

	private Map<String, Object> preProcessInvocationRequest(
			final String commandName, final List<String> parameters) {
		int index = 0;
		final Map<String, Object> invocationParamsMap = new HashMap<String, Object>();

		// add command
		invocationParamsMap.put(
				CloudifyConstants.INVOCATION_PARAMETER_COMMAND_NAME,
				commandName);

		if (parameters != null) {
			for (final String param : parameters) {
				invocationParamsMap.put(
						CloudifyConstants.INVOCATION_PARAMETERS_KEY + index,
						param);
				++index;
			}
		}

		return invocationParamsMap;

	}

	private Map<String, String> postProcessInvocationResult(
			final String instanceName, final Object result) {

		final Map<String, String> resultsMap = new HashMap<String, String>();
		resultsMap.put(CloudifyConstants.INVOCATION_RESPONSE_INSTANCE_NAME,
				instanceName);

		if (result instanceof Map<?, ?>) {
			@SuppressWarnings("unchecked")
			final Set<Entry<String, Object>> entries = ((Map<String, Object>) result)
					.entrySet();
			for (final Entry<String, Object> subEntry : entries) {
				String key = subEntry.getKey();
				String safeValue = subEntry.getValue() == null ? null
						: subEntry.getValue().toString();

				if (key.equalsIgnoreCase(CloudifyConstants.INVOCATION_RESPONSE_STATUS)) {
					if (Boolean.parseBoolean(safeValue)) {
						resultsMap
								.put(key, InvocationStatus.SUCCESS.toString());
					} else {
						resultsMap
								.put(key, InvocationStatus.FAILURE.toString());
					}
				} else {
					resultsMap.put(key, safeValue);
				}
			}
		} else {
			resultsMap.put(CloudifyConstants.INVOCATION_RESPONSE_STATUS,
					InvocationStatus.UNEXPECTED.toString());
			resultsMap.put(CloudifyConstants.INVOCATION_RESPONSE_RESULT,
					result == null ? null : result.toString());
		}

		return resultsMap;
	}

	private String buildServiceInstanceName(
			final ProcessingUnitInstance instance) {
		return "instance #" + instance.getInstanceId() + "@"
				+ instance.getVirtualMachine().getMachine().getHostName();
	}

	private InternalProcessingUnitInstance findInstanceById(
			final ProcessingUnit pu, final int id) {
		final ProcessingUnitInstance[] instances = pu.getInstances();
		for (final ProcessingUnitInstance instance : instances) {
			if (instance.getInstanceId() == id) {
				return (InternalProcessingUnitInstance) instance;
			}
		}
		return null;
	}

}
