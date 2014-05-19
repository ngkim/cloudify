/*******************************************************************************
 * Copyright (c) 2011 GigaSpaces Technologies Ltd. All rights reserved
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
package org.cloudifysource.rest.controllers.exceptions;

import org.apache.commons.lang.StringUtils;

/**
 * @author noak
 * @since 2.0.0
 * 
 *        Extends {@link CLIException}, includes more details to support
 *        validation errors.
 */
public class CLIValidationException extends CLIException {

	private static final long serialVersionUID = 4004719704284906595L;
	
	private final int exitCode;
	private final String reasonCode;
	private final String verboseData;
	private final Object[] args;


	/**
	 * Constructor.
	 * 
	 * @param cause
	 *            The Throwable that caused this exception to be thrown.
	 * @param reasonCode
	 *            A reason code, by which a formatted message can be retrieved
	 *            from the message bundle
	 * @param exitCode
	 *            The JVM will exit with the given exit code
	 * @param args
	 *            Optional arguments to embed in the formatted message
	 */
	public CLIValidationException(final Throwable cause, final int exitCode, final String reasonCode, 
			final Object... args) {
		super("reasonCode: " + reasonCode, cause);
		this.exitCode = exitCode;
		this.args = args;
		this.reasonCode = reasonCode;
		this.verboseData = null;
	}

	/**
	 * Constructor.
	 * 
	 * @param exitCode
	 *            The JVM will exit with the given exit code
	 * @param reasonCode
	 *            A reason code, by which a formatted message can be retrieved
	 *            from the message bundle
	 * @param args
	 *            Optional arguments to embed in the formatted message
	 */
	public CLIValidationException(final int exitCode, final String reasonCode, final Object... args) {
		super("reasonCode: " + reasonCode);
		this.exitCode = exitCode;
		this.reasonCode = reasonCode;
		this.args = args;
		this.verboseData = null;
	}
	
	
	/**
	 * Gets the exit code.
	 * 
	 * @return The exit code related to this validation exception
	 */
	public int getExitCode() {
		return exitCode;
	}

	/**
	 * Gets the reason code.
	 * 
	 * @return A reason code, by which a formatted message can be retrieved from
	 *         the message bundle
	 */
	public String getReasonCode() {
		return reasonCode;
	}

	/**
	 * Gets the arguments that complete the reason-code based message.
	 * 
	 * @return An array of arguments
	 */
	public Object[] getArgs() {
		return args;
	}
	
	/**
	 * Gets the verbose data.
	 * @return verbose data
	 */
	public String getVerboseData() {
		return verboseData;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return "CLIValidationException, reason code: " + reasonCode + ", message arguments: "
				+ StringUtils.join(args, ", ");
	}

}
