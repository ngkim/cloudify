package org.cloudifysource.dsl.rest.response;

/**
 * POJO result of a uninstall service request via the REST gateway.
 * 
 * @author ngkim
 * 
 */
public class UninstallServiceResult {
	private String deploymentID = "";
	private String serviceName = "";
	private int resultStatus = 1;  // 1: success, -1: fail
	private String resultMsg = "";

	public String getDeploymentID() {
		return deploymentID;
	}

	public void setDeploymentID(String deploymentID) {
		this.deploymentID = deploymentID;
	}

	public String getServiceName() {
		return serviceName;
	}

	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
	}

	public int getResultStatus() {
		return resultStatus;
	}

	public void setResultStatus(int result) {
		this.resultStatus = result;
	}

	public String getResultMsg() {
		return resultMsg;
	}

	public void setResultMsg(String resultMsg) {
		this.resultMsg = resultMsg;
	}

}
