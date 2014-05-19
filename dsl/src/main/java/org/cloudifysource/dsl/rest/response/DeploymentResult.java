package org.cloudifysource.dsl.rest.response;

/**
 * POJO result of a deployment status request via the REST gateway.
 * 
 * @author ngkim
 * 
 */
public class DeploymentResult {
	private String mgmtUrl;

	public String getMgmtUrl() {
		return mgmtUrl;
	}

	public void setMgmtUrl(String mgmtUrl) {
		this.mgmtUrl = mgmtUrl;
	}

}
