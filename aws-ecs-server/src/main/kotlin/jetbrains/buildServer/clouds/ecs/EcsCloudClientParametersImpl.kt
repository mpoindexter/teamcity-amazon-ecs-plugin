/*
 * Copyright 2000-2021 JetBrains s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jetbrains.buildServer.clouds.ecs

import com.amazonaws.auth.*
import com.amazonaws.services.securitytoken.AWSSecurityTokenService
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest
import jetbrains.buildServer.clouds.CloudClientParameters
import jetbrains.buildServer.util.StringUtil
import jetbrains.buildServer.util.amazon.AWSClients.MAX_SESSION_NAME_LENGTH
import jetbrains.buildServer.util.amazon.AWSClients.UNSUPPORTED_SESSION_NAME_CHARS
import jetbrains.buildServer.util.amazon.AWSCommonParams
import jetbrains.buildServer.util.amazon.AWSCommonParams.*
import java.util.*
import java.util.concurrent.atomic.AtomicReference


fun CloudClientParameters.toEcsParams() : EcsCloudClientParameters = EcsCloudClientParametersImpl(this)

class EcsCloudClientParametersImpl(private val genericParams: CloudClientParameters) : EcsCloudClientParameters {
    override val region: String
        get() = AWSCommonParams.getRegionName(genericParams.parameters)!!

    override val instanceLimit: Int
        get() {
            val parameter = genericParams.getParameter(PROFILE_INSTANCE_LIMIT_PARAM)
            return if (StringUtil.isEmpty(parameter)) -1 else Integer.valueOf(parameter)
        }

    override val imagesData: List<EcsCloudImageData>
        get() = genericParams.cloudImages.map { EcsCloudImageData(it) }

    //NOTE: copy pasted from jetbrains.buildServer.util.amazon.AWSCommonParams

    override val awsCredentialsProvider: AWSCredentialsProvider?
        get() {
            return genericParams.parameters.toAwsCredentialsProvider()
        }
}

fun Map<String, String>.toAwsCredentialsProvider(): AWSCredentialsProvider? {
    return getCredentialsProvider(this, false)
}

private fun getCredentialsProvider(params: Map<String, String>, fixedCredentials: Boolean): AWSCredentialsProvider {
    val credentialsType = getCredentialsType(params)

    if (isAccessKeysOption(credentialsType) || fixedCredentials) {
        return if (isUseDefaultCredentialProviderChain(params)) {
            DefaultAWSCredentialsProviderChain()
        } else object : AWSCredentialsProvider {
            override fun getCredentials(): AWSCredentials {
                return BasicAWSCredentials(getAccessKeyId(params), getSecretAccessKey(params))
            }

            override fun refresh() {
                // do nothing
            }
        }
    } else if (isTempCredentialsOption(credentialsType)) {
        return object : AWSSessionCredentialsProvider {
            private val mySessionCredentials: AtomicReference<AWSSessionCredentials> =
                AtomicReference<AWSSessionCredentials>()

            override fun getCredentials(): AWSSessionCredentials {
                if (mySessionCredentials.get() == null) {
                    synchronized(this) {
                        if (mySessionCredentials.get() == null) {
                            mySessionCredentials.set(createSessionCredentials(params))
                        }
                    }
                }
                return mySessionCredentials.get()
            }

            override fun refresh() {
                synchronized(this) {
                    mySessionCredentials.set(createSessionCredentials(params))
                }
            }
        }
    }

    return object : AWSCredentialsProvider {
        override fun getCredentials(): AWSCredentials {
            return BasicAWSCredentials("", "")
        }

        override fun refresh() {}
    }
}

private fun isAccessKeysOption(credentialsType: String?): Boolean {
    return ACCESS_KEYS_OPTION == credentialsType || ACCESS_KEYS_OPTION_OLD == credentialsType
}

private fun isTempCredentialsOption(credentialsType: String?): Boolean {
    return TEMP_CREDENTIALS_OPTION == credentialsType || TEMP_CREDENTIALS_OPTION_OLD == credentialsType
}

private fun getCredentialsType(params: Map<String, String>): String? {
    return getNewOrOld(params, CREDENTIALS_TYPE_PARAM, CREDENTIALS_TYPE_PARAM_OLD)
}

private fun isUseDefaultCredentialProviderChain(params: Map<String, String>): Boolean {
    return java.lang.Boolean.parseBoolean(params[USE_DEFAULT_CREDENTIAL_PROVIDER_CHAIN_PARAM]) || java.lang.Boolean.parseBoolean(USE_DEFAULT_CREDENTIAL_PROVIDER_CHAIN_PARAM_OLD)
}

private fun getAccessKeyId(params: Map<String, String>): String? {
    return getNewOrOld(params, ACCESS_KEY_ID_PARAM, ACCESS_KEY_ID_PARAM_OLD)
}

private fun getSecretAccessKey(params: Map<String, String>): String? {
    var secretAccessKeyParam = params[SECURE_SECRET_ACCESS_KEY_PARAM]
    if (StringUtil.isNotEmpty(secretAccessKeyParam)) return secretAccessKeyParam

    secretAccessKeyParam = params[SECURE_SECRET_ACCESS_KEY_PARAM_OLD]
    return if (StringUtil.isNotEmpty(secretAccessKeyParam)) secretAccessKeyParam else params[SECRET_ACCESS_KEY_PARAM_OLD]
}

private fun getIamRoleArnParam(params: Map<String, String>): String? {
    return getNewOrOld(params, IAM_ROLE_ARN_PARAM, IAM_ROLE_ARN_PARAM_OLD)
}


private fun getNewOrOld(params: Map<String, String>, newKey: String, oldKey: String): String? {
    val newVal = params[newKey]
    return if (StringUtil.isNotEmpty(newVal)) newVal else params[oldKey]
}

fun patchSessionDuration(sessionDuration: Int): Int {
    if (sessionDuration < 900)
        return 900
    return if (sessionDuration > 3600)
        3600
    else
        sessionDuration
}

fun patchSessionName(sessionName: String): String? {
    return StringUtil.truncateStringValue(
        sessionName.replace(UNSUPPORTED_SESSION_NAME_CHARS.toRegex(), "_"),
        MAX_SESSION_NAME_LENGTH
    )
}

private fun createSecurityTokenService(params: Map<String, String>): AWSSecurityTokenService {
    val region = getRegionName(params)
    return AWSSecurityTokenServiceClientBuilder
        .standard()
        .withRegion(region)
        .withCredentials(getCredentialsProvider(params, true))
        .build()
}

private fun createSessionCredentials(params: Map<String, String>): AWSSessionCredentials? {
    val iamRoleARN = getIamRoleArnParam(params)
    val sessionName = getStringOrDefault(
        params[TEMP_CREDENTIALS_SESSION_NAME_PARAM],
        TEMP_CREDENTIALS_SESSION_NAME_DEFAULT_PREFIX + Date().time
    )
    val sessionDuration =
        getIntegerOrDefault(params[TEMP_CREDENTIALS_DURATION_SEC_PARAM], TEMP_CREDENTIALS_DURATION_SEC_DEFAULT)
    val assumeRoleRequest = AssumeRoleRequest()
        .withRoleArn(iamRoleARN)
        .withRoleSessionName(patchSessionName(sessionName))
        .withDurationSeconds(patchSessionDuration(sessionDuration))
        val securityTokenService = createSecurityTokenService(params)
        val credentials = securityTokenService.assumeRole(assumeRoleRequest).credentials
        return BasicSessionCredentials(
            credentials.accessKeyId,
            credentials.secretAccessKey,
            credentials.sessionToken
        )
}