package org.cloudifysource.dsl.rest.response;

/**
 * POJO result of a deployment status request via the REST gateway.
 * 
 * @author ngkim
 * 
 */
public class DeploymentStatus {
	private String totalSteps;
	private String currentStep;
	private String status;
	private String message;
	private String time;
	
	public String getTotalSteps() {
		return totalSteps;
	}

	public void setTotalSteps(String totalSteps) {
		this.totalSteps = totalSteps;
	}

	public String getCurrentStep() {
		return currentStep;
	}

	public void setCurrentStep(String currentStep) {
		this.currentStep = currentStep;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getTime() {
		return time;
	}

	public void setTime(String time) {
		this.time = time;
	}

}
