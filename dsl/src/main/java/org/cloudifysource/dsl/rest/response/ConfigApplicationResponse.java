/*******************************************************************************
 * Copyright (c) 2013 GigaSpaces Technologies Ltd. All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.cloudifysource.dsl.rest.response;

import java.util.Map;

/**
 * POJO representation of an configApplication command request via the REST gateway.
 * 
 * @author ngkim
 *
 */
public class ConfigApplicationResponse {
	
	private String appName;
	private String adminPassword;
	private String rootPassword;
	
	private String domainName;
	private String hostName;
	private String deviceName;
	
	private String greenZoneIpAddress;
	private String greenZoneBroadcast;
	private String greenZoneNetwork;
	private String greenZoneNetmask;
	private String greenZoneInterface;
	
	private String orangeZoneIpAddress;
	private String orangeZoneBroadcast;
	private String orangeZoneNetwork;
	private String orangeZoneNetmask;
	private String orangeZoneInterface;
	
	private String redZoneIpAddress;
	private String redZoneBroadcast;
	private String redZoneNetwork;
	private String redZoneNetmask;
	private String redZoneInterface;
	
	private String deploymentID;
	
	public String getAppName() {
		return appName;
	}

	public void setAppName(String appName) {
		this.appName = appName;
	}

	public String getAdminPassword() {
		return adminPassword;
	}

	public void setAdminPassword(String adminPassword) {
		this.adminPassword = adminPassword;
	}

	public String getRootPassword() {
		return rootPassword;
	}

	public void setRootPassword(String rootPassword) {
		this.rootPassword = rootPassword;
	}

	public String getDomainName() {
		return domainName;
	}

	public void setDomainName(String domainName) {
		this.domainName = domainName;
	}

	public String getHostName() {
		return hostName;
	}

	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	public String getDeviceName() {
		return deviceName;
	}

	public void setDeviceName(String deviceName) {
		this.deviceName = deviceName;
	}

	public String getGreenZoneIpAddress() {
		return greenZoneIpAddress;
	}

	public void setGreenZoneIpAddress(String greenZoneIpAddress) {
		this.greenZoneIpAddress = greenZoneIpAddress;
	}

	public String getGreenZoneBroadcast() {
		return greenZoneBroadcast;
	}

	public void setGreenZoneBroadcast(String greenZoneBroadcast) {
		this.greenZoneBroadcast = greenZoneBroadcast;
	}

	public String getGreenZoneNetwork() {
		return greenZoneNetwork;
	}

	public void setGreenZoneNetwork(String greenZoneNetwork) {
		this.greenZoneNetwork = greenZoneNetwork;
	}

	public String getGreenZoneNetmask() {
		return greenZoneNetmask;
	}

	public void setGreenZoneNetmask(String greenZoneNetmask) {
		this.greenZoneNetmask = greenZoneNetmask;
	}

	public String getGreenZoneInterface() {
		return greenZoneInterface;
	}

	public void setGreenZoneInterface(String greenZoneInterface) {
		this.greenZoneInterface = greenZoneInterface;
	}

	public String getOrangeZoneIpAddress() {
		return orangeZoneIpAddress;
	}

	public void setOrangeZoneIpAddress(String orangeZoneIpAddress) {
		this.orangeZoneIpAddress = orangeZoneIpAddress;
	}

	public String getOrangeZoneBroadcast() {
		return orangeZoneBroadcast;
	}

	public void setOrangeZoneBroadcast(String orangeZoneBroadcast) {
		this.orangeZoneBroadcast = orangeZoneBroadcast;
	}

	public String getOrangeZoneNetwork() {
		return orangeZoneNetwork;
	}

	public void setOrangeZoneNetwork(String orangeZoneNetwork) {
		this.orangeZoneNetwork = orangeZoneNetwork;
	}

	public String getOrangeZoneNetmask() {
		return orangeZoneNetmask;
	}

	public void setOrangeZoneNetmask(String orangeZoneNetmask) {
		this.orangeZoneNetmask = orangeZoneNetmask;
	}

	public String getOrangeZoneInterface() {
		return orangeZoneInterface;
	}

	public void setOrangeZoneInterface(String orangeZoneInterface) {
		this.orangeZoneInterface = orangeZoneInterface;
	}

	public String getRedZoneIpAddress() {
		return redZoneIpAddress;
	}

	public void setRedZoneIpAddress(String redZoneIpAddress) {
		this.redZoneIpAddress = redZoneIpAddress;
	}

	public String getRedZoneBroadcast() {
		return redZoneBroadcast;
	}

	public void setRedZoneBroadcast(String redZoneBroadcast) {
		this.redZoneBroadcast = redZoneBroadcast;
	}

	public String getRedZoneNetwork() {
		return redZoneNetwork;
	}

	public void setRedZoneNetwork(String redZoneNetwork) {
		this.redZoneNetwork = redZoneNetwork;
	}

	public String getRedZoneNetmask() {
		return redZoneNetmask;
	}

	public void setRedZoneNetmask(String redZoneNetmask) {
		this.redZoneNetmask = redZoneNetmask;
	}

	public String getRedZoneInterface() {
		return redZoneInterface;
	}

	public void setRedZoneInterface(String redZoneInterface) {
		this.redZoneInterface = redZoneInterface;
	}

	public String getDeploymentID() {
		return deploymentID;
	}

	public void setDeploymentID(String deploymentID) {
		this.deploymentID = deploymentID;
	}
	
}
