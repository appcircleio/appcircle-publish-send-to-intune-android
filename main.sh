
#!/bin/bash
# install jq to use this script
# Obtain these values before the component starts. (from env, etc..)

brew install jq

echo "AndroidFileName:$AndroidFileName"
echo "AndroidFileUrl:$AndroidFileUrl"
echo "AppName:$AppName"
echo "BundleId:$UniqueName"
echo "OrganizationName:$OrganizationName"
echo "UserEmail:$UserEmail"
echo "IconFileName:$IconFileName"
echo "IconUrl:$IconUrl"
echo "ACOutputDir:$AC_OUTPUT_DIR"


locale
## Get app binary
curl -o "./$AndroidFileName" -k $AndroidFileUrl

## Get app icon
curl -o "./$IconFileName" -k $IconUrl

authUrl="$AC_CREDENTIAL_INTUNE_CLIENT_AUTH_URL"
clientId="$AC_CREDENTIAL_INTUNE_CLIENT_ID"
clientSecret="$AC_CREDENTIAL_INTUNE_CLIENT_SECRET"
inTuneAppId="$AC_INTUNE_APP_ID"
minOsVersion="$AC_INTUNE_MIN_OS_VERSION"
targetedPlaform="$AC_INTUNE_TARGETED_PLATFORM"

# Variables
accessToken=""
baseUrl="https://graph.microsoft.com/beta"
scope="https://graph.microsoft.com/.default"
grant_type="client_credentials"
sleep=10
encrypted_file_name="encrpyted_file.bin"


function printInfo {
    local message=$1
    echo -e "\033[1;33m${message}\033[0m"
}

function printError {
    local message="$1"
    echo -e "\033[1;31m${message}\033[0m"
}

function printSuccess {
    local message=$1
    echo -e "\033[1;32m${message}\033[0m"
}

getAppIconBody(){
    if [ -n "${IconFileName}" ]; then
        mime_type=$(file --mime-type -b "$IconFileName")
        base64_image=$(base64 < "$IconFileName" | tr -d '\n')
        json_output=$(jq -n --arg mimeType "$mime_type" --arg value "$base64_image" \
    '{type: $mimeType, value: $value}')
        echo "$json_output"
    else 
        echo ""
    fi    
}


makeRequest(){
    local verb="$1"
    local collectionPath="$2"
    local body="$3"

    local uri="$baseUrl$collectionPath"
    local request="$verb $uri"

    contentType="application/json"
    contentLength="${#body}"
    authorization="Bearer $accessToken"
    response=$(curl -X "$verb" -H "Content-Type: $contentType" -H "Content-Length: $contentLength" -H "Authorization: $authorization" -d "$body" "$uri" 2>/dev/null)
    echo $response
}



getAccessToken(){
 response=$(curl --location "$authUrl"\
                --header 'Content-Type: application/x-www-form-urlencoded' \
                --data-urlencode "client_id=${clientId}" \
                --data-urlencode "client_secret=${clientSecret}" \
                --data-urlencode "scope=${scope}" \
                --data-urlencode "grant_type=${grant_type}" \
                2>/dev/null)

 accessToken=$(echo "$response" | jq -r '.access_token')
}



function makeGetRequest(){
    local collectionPath="$1"
    local uri="$baseUrl$collectionPath"
    local request="GET $uri"
    contentType="application/json"
    authorization="Bearer $accessToken"
    response=$(curl -X GET -H "Content-Type: $contentType" -H "Authorization: $authorization" "$uri" 2>/dev/null)
    echo "$response"
}



function makePatchRequest(){
    local collectionPath="$1"
    local body="$2"
	response=$(makeRequest "PATCH" "$collectionPath" "$body")
    echo $response
}



function makePostRequest(){
    local collectionPath="$1"
    local body="$2"
	response=$(makeRequest "POST" "$collectionPath" "$body")
    echo $response
}



testSourceFile(){
    local sourceFile="$1"

    if test -e "$sourceFile"; then
        printSuccess "Source file exists."
    else
        printError "Source File '$sourceFile' doesn't exist..."
        exit 1
    fi
}



generateKey(){
  local num_bytes="0"
  local key
  while [ "$num_bytes" -ne "44" ]; do
  # Generate random hexadecimal string
  key=$(openssl rand -hex 32)
  base64_encoded=$(echo -n $key | xxd -r -p | base64 )

  # Count the number of bytes
  num_bytes=${#base64_encoded}

  done

  echo $key
}

generateIV(){
  local num_bytes="0"
  local key
  while [ "$num_bytes" -ne "24" ]; do
  # Generate random hexadecimal string
  key=$(openssl rand -hex 16)
  base64_encoded=$(echo -n $key | xxd -r -p | base64 )

  # Count the number of bytes
  num_bytes=${#base64_encoded}

  done

  echo $key
}

encryptFile(){
    local source_file="$1"
    local target_file="$2"
    encryptionKey=$(generateKey)
    initializationVector=$(generateIV)
    hmacKey=$(generateKey)
    combined_file=$(mktemp combined_file.bin)
    temp_file=$(mktemp tmp.bin)
    # Encrypt the .ipa file using AES-256-CBC
    file="$source_file"
    encryptedFile="$target_file"
    openssl enc -aes-256-cbc -K "$encryptionKey" -iv "$initializationVector" -in "$file" -out "$encryptedFile"
    
    # Append IV to the end of the file
    echo "${initializationVector}" | xxd -r -p >> "$temp_file"
    cat "$temp_file" "$encryptedFile" > "$combined_file"
    echo -n "" | dd of="$encryptedFile" bs=1 seek=0 count=0
    cat "$combined_file" > "$encryptedFile"
    echo -n "" | dd of="$combined_file" bs=1 seek=0 count=0
    echo -n "" | dd of="$temp_file" bs=1 seek=0 count=0
    
    # Calculate and append HMAC
    # shellcheck disable=SC2094,SC2002
    mac=$(cat "${encryptedFile}" | openssl dgst -sha256 -mac hmac -macopt hexkey:"${hmacKey}" | awk '{print $NF}')
    echo "${mac}" | xxd -r -p >> "$temp_file"
    cat "$temp_file" "$encryptedFile" > "$combined_file"
    echo -n "" | dd of="$encryptedFile" bs=1 seek=0 count=0
    cat "$combined_file" > "$encryptedFile"
    echo -n "" | dd of="$combined_file" bs=1 seek=0 count=0
    echo -n "" | dd of="$temp_file" bs=1 seek=0 count=0

    # Encode keys and vectors in base64
    encryptionKeyBase64=$(echo -n $encryptionKey | xxd -r -p | base64 )
    initializationVectorBase64=$(echo -n $initializationVector | xxd -r -p | base64 )
    hmacKeyBase64=$(echo -n $hmacKey | xxd -r -p | base64 )
    macBase64=$(echo -n $mac | xxd -r -p | base64 )
    
    # Compute the SHA256 hash (file digest) of the original .ipa file
    fileDigest=$(openssl dgst -sha256 -binary "$file" | base64)

    encryptionInfo=$(printf '{"fileEncryptionInfo":{"encryptionKey":"%s","macKey":"%s","initializationVector":"%s","mac":"%s","profileIdentifier":"ProfileVersion1","fileDigest":"%s","fileDigestAlgorithm":"SHA256"}} \n' \
    "$encryptionKeyBase64" "$hmacKeyBase64" "$initializationVectorBase64" "$macBase64" "$fileDigest" | jq -c .)
    
    rm "$combined_file"
    rm "$temp_file"

    echo "$encryptionInfo";
}



getAndroidAppBody(){
    local displayName="$1"
    local publisher="$2"
    local description="$3"
    local filename="$4"
    local bundleId="$5"
    local identityVersion="$6"
    local versionName="$7"

    iconBody=$(getAppIconBody)
    if([ -n "$iconBody" ]); then
    cat <<EOF
{
    "@odata.type": "#microsoft.graph.androidLOBApp",
    "categories": [],
    "description": "$description",
    "developer": "",
    "displayName": "$displayName",
    "fileName": "$filename",
    "informationUrl": null,
    "isFeatured": false,
    "minimumSupportedOperatingSystem": {
        "$minOsVersion": true
    },
    "notes": "",
    "owner": "",
    "packageId": "$bundleId",
    "privacyInformationUrl": null,
    largeIcon:$(echo "$iconBody" | jq -c .),
    "publisher": "$publisher",
    "roleScopeTagIds": [],
    "targetedPlatforms" : "$targetedPlaform",
    "versionCode": "$identityVersion",
    "versionName": "$versionName"
}
EOF
   else
       cat <<EOF
{
    "@odata.type": "#microsoft.graph.androidLOBApp",
    "categories": [],
    "description": "$description",
    "developer": "",
    "displayName": "$displayName",
    "fileName": "$filename",
    "informationUrl": null,
    "isFeatured": false,
    "minimumSupportedOperatingSystem": {
        "$minOsVersion": true
    },
    "notes": "",
    "owner": "",
    "packageId": "$bundleId",
    "privacyInformationUrl": null,
    "publisher": "$publisher",
    "roleScopeTagIds": [],
    "targetedPlatforms" : "$targetedPlaform",
    "versionCode": "$identityVersion",
    "versionName": "$versionName"
}
EOF
   fi
}

generateAndroidManifest() {
    local displayName="$1"
    local bundleId="$2"
    local identityVersion="$3"
    local versionName="$4"
    manifestXML='<?xml version="1.0" encoding="utf-8"?><AndroidManifestProperties xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Package>bundleid</Package><PackageVersionCode>bundleversion</PackageVersionCode><PackageVersionName>bundleversionname</PackageVersionName><ApplicationName>bundletitle</ApplicationName><MinSdkVersion>21</MinSdkVersion><AWTVersion></AWTVersion></AndroidManifestProperties>'

    # Replace placeholders with actual values
    manifestXML="${manifestXML//bundleid/$bundleId}"
    manifestXML="${manifestXML//bundleversion/$identityVersion}"
    manifestXML="${manifestXML//bundletitle/$displayName}"
    manifestXML="${manifestXML//bundleversionname/$versionName}"

    # Convert the manifest XML to ASCII bytes and then to Base64
    encodedText=$(echo "$manifestXML" | base64)

    echo "$encodedText" 
}

getAppFileBody(){
    local name="$1"
    local size="$2"
    local sizeEncrypted="$3"
    local manifest="$4"

    cat <<EOF
{
    "@odata.type": "#microsoft.graph.mobileAppContentFile",
    "name": "$name",
    "size": $size,
    "sizeEncrypted": $sizeEncrypted,
    "manifest": "$manifest"
}
EOF
}

waitForFileProcessing(){
    local fileUri="$1"
    local stage="$2"

    local attempts=60
    local waitTimeInSeconds=1

    local successState="${stage}Success"
    local pendingState="${stage}Pending"
    local failedState="${stage}Failed"
    local timedOutState="${stage}TimedOut"

    local file

    while [ "$attempts" -gt 0 ]; do
        file=$(makeGetRequest "$fileUri")
        uploadState=$(echo "$file" | jq -r '.uploadState')
        if [ "${uploadState}" = "$successState" ]; then
            break
        elif [ "${uploadState}" != "$pendingState" ]; then
            printError "File upload state is not success: ${uploadState}"
            break
        fi

        sleep "$waitTimeInSeconds"
        ((attempts--))
    done

    if [ -z "$file" ]; then
        printError "File request did not complete in the allotted time."
    fi

    echo "$file"
}

finalizeAzureStorageUpload(){
    local sasUri="$1"
    shift
    local ids=("$@")

    # Convert IDs array to comma-separated string
    local idString=$(IFS=','; echo "${ids[*]}")

    # Construct URI for finalizing upload
    local uri="$sasUri&comp=blocklist"

    # Construct XML block list
    local blockList='<?xml version="1.0" encoding="utf-8"?><BlockList>'
    for id in "${ids[@]}"; do
        blockList+="<Latest>$id</Latest>"
    done
    blockList+="</BlockList>"

    # Finalize the upload using curl
    local response
    response=$(curl -X PUT -H "Content-Type: application/xml" --data "$blockList" "$uri" 2>&1)
    echo $response;
    if [ $? -ne 0 ]; then
        printError "Error occurred while finalizing upload: $response"
        exit 1
    fi
}

uploadAzureStorageChunk(){
    local sasUri="$1"
    local id="$2"
    local filePath="$3"

    # Construct URI for the upload
    local uri="$sasUri&comp=block&blockid=$id"


    # Upload the chunk using curl
    local response
    response=$(curl -X PUT -H "Content-Type: application/octet-stream" --data-binary "@$filePath" "$uri" 2>&1)
    echo $response;

    if [ $? -ne 0 ]; then
        printError "Error occurred while uploading chunk $id: $response"
        exit 1
    fi
}
uploadFileToAzureStorage(){
    local sasUri="$1"
    local filepath="$2"

    split -b 1M "$filepath" "block-"
    block_parts=($(ls block-*))
    block_size=${#block_parts[@]}
    # Upload each chunk
    local ids=()
    local cc=1
    for (( chunk = 0; chunk < $block_size; chunk++ )); do
        local id=$(printf "block-%08d" $chunk | base64)
        ids+=("$id")
        block_path=${block_parts[$chunk]}
        echo "Uploading chunk $cc of $block_size"
        uploadAzureStorageChunk "$sasUri" "$id" "$block_path"
        ((cc++))
    done
    cc=1
    for (( chunk = 0; chunk < $block_size; chunk++ )); do
        block_path=${block_parts[$chunk]}
        rm "$block_path"
        ((cc++))
    done

    printInfo "Finalizing upload"
    finalizeAzureStorageUpload "$sasUri" "${ids[@]}"
}

getAppCommitBody(){
    local contentVersionId="$1"
    local LobType="$2"

    cat <<EOF
{
    "@odata.type": "#$LobType",
    "committedContentVersion": "$contentVersionId"
}
EOF
}

createAndUploadAndroidLobApp(){
    local sourceFile="$1"
    local displayName="$2"
    local publisher="$3"
    local description="$4"
    local bundleId="$5"
    local identityVersion="$6"
    local versionName="$7"

    LOBType="microsoft.graph.androidLOBApp"

    printInfo "Testing if source file exists: $sourceFile"
    testSourceFile "$sourceFile"

    # Creating temp file name from Source File path
    temp_file="$encrypted_file_name"

    filename=$(basename "$sourceFile")
    printInfo "Obtaining access token..."
    getAccessToken

    updateApp="false"
    if [ -z "${inTuneAppId// }" ]; then
        updateApp="false"
    else
        printInfo "Searching app in Intune..."
        publishedApp=$(makeGetRequest "/deviceAppManagement/mobileApps/$inTuneAppId")
        error=$(echo "$publishedApp" | jq -r '.error')
        if [ "$error" != "null" ]; then
            printError "Error occurred: $publishedApp"
            exit 1
        fi
        updateApp="true"
        appId=$(echo "$publishedApp" | jq -r '.id')
    fi

    if [ "$updateApp" = "false" ]; then
        printInfo "Creating JSON data to pass to the service..."
        mobileAppBody=$(getAndroidAppBody "$displayName" "$publisher" "$description" "$filename" "$bundleId" "$identityVersion" "$versionName")
        printInfo "Creating application in Intune..."
        mobileApp=$(makePostRequest "/deviceAppManagement/mobileApps" "$mobileAppBody")
        error=$(echo "$mobileApp" | jq -r '.error')
        if [ "$error" != "null" ]; then
            printError "Error occurred: $error"
            exit 1
        fi
        appId=$(echo "$mobileApp" | jq -r '.id')
        printInfo "Application created with ID: $appId"
        echo "CreatedIntuneAppId=$appId" >> "$AC_OUTPUT_DIR/AC_OUTPUT.env"
    fi

    printInfo "Creating Content Version in the service for the application..."
    contentVersionUri="/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions"
    contentVersion=$(makePostRequest "$contentVersionUri" "{}")
    error=$(echo "$contentVersion" | jq -r '.error')
    if [ "$error" != "null" ]; then
        printError "Error occurred: $error"
        exit 1
    fi
    printInfo "Ecrypting the file '$sourceFile'..."

    encryptionInfo=$(encryptFile "$sourceFile" "$temp_file")
    # Get the size of the source file
    size=$(stat -f %z "$sourceFile")
    # Get the size of the temporary file (assuming it's the encrypted file)
    encryptedSize=$(stat -f %z "$temp_file")

    printInfo "Creating the manifest file used to install the application on the device..."
    
    manifestXMLBase64=$(generateAndroidManifest "$displayName" "$bundleId" "$identityVersion" "$versionName")

    printInfo "Creating a new file entry in Azure for the upload..."
    
    contentVersionId=$(echo "$contentVersion" | jq -r '.id')
    fileBody=$(getAppFileBody "$filename" "$size" "$encryptedSize" "$manifestXMLBase64")
    filesUri="/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files";
    file=$(makePostRequest "$filesUri" "$fileBody")
    error=$(echo "$file" | jq -r '.error')
    if [ "$error" != "null" ]; then
        printError "Error occurred: $error"
        exit 1
    fi

    printInfo "Waiting for the file entry URI to be created..."
    fileId=$(echo "$file" | jq -r '.id')
    fileUri="/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId"
    file=$(waitForFileProcessing "$fileUri" "azureStorageUriRequest")

    error=$(echo "$file" | jq -r '.error')
    if [ "$error" != "null" ]; then
        printError "Error occurred: $error"
        exit 1
    fi
    printInfo "Uploading file to Azure Storage..."
    sasUri=$(echo "$file" | jq -r '.azureStorageUri')
    uploadFileToAzureStorage "$sasUri" "$temp_file"

    printInfo "Committing the file into Azure Storage.."
    commitFileUri="/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit";
    response=$(makePostRequest "$commitFileUri" "$encryptionInfo")

    printInfo "Waiting for the service to process the commit file request..."
    file=$(waitForFileProcessing "$fileUri" "commitFile")
    error=$(echo "$file" | jq -r '.error')
    if [ "$error" != "null" ]; then
        printError "Error occurred: $error"
        exit 1
    fi

    printInfo "Committing the App..."
    commitAppUri="/deviceAppManagement/mobileApps/$appId"
    if [ "$updateApp" = "false" ]; then
        commitAppBody=$(getAppCommitBody "$contentVersionId" "$LOBType")
    else
        minimumSupportedOperatingSystem=$(printf '{
        "%s": true
        }' "$minOsVersion")
        commitAppBody=$(echo "$publishedApp" | jq 'del(.id, .size, .["@odata.context"], .bunleId, .createdDateTime, .identityVersion, .lastModifiedDateTime, .publishingState, .uploadState, .isAssigned, .roleScopeTagIds, .dependentAppCount, .supersedingAppCount, .supersededAppCount, .targetedPlatforms )' | jq \
            --arg LOBType "#$LOBType" \
            --arg contentVersionId "$contentVersionId" \
            --arg displayName "$displayName" \
            --arg description "$description" \
            --arg filename "$filename" \
            --arg versionCode "$identityVersion" \
            --arg versionName "$versionName" \
            --arg publisher "$publisher" \
            --argjson minimumSupportedOperatingSystem "$minimumSupportedOperatingSystem" \
            '
            .["@odata.type"] = $LOBType |
            .committedContentVersion = $contentVersionId |
            .displayName = $displayName |
            .description = $description |
            .fileName = $filename |
            .versionCode = $versionCode |
            .publisher = $publisher |
            .versionName = $versionName |
            .minimumSupportedOperatingSystem = $minimumSupportedOperatingSystem
            ')
    fi
    response=$(makePatchRequest "$commitAppUri" "$commitAppBody")

    printInfo "Removing Temporary file"
    rm "$temp_file"

    printInfo "Sleeping for $sleep seconds to allow patch completion..."
    sleep "$sleep"

    printSuccess "App published successfully"
}



 PUBLISHER=""

 if [ -n "${AC_INTUNE_PUBLISHER_NAME}" ]; then
        PUBLISHER="$AC_INTUNE_PUBLISHER_NAME"
        printInfo "Publisher Name: $PUBLISHER"
 elif [ -n "${OrganizationName}" ]; then
        PUBLISHER="$OrganizationName"
        printInfo "Publisher Name: $PUBLISHER"
 elif [ -n "${UserEmail}" ]; then
        PUBLISHER="$UserEmail"
        printInfo "Publisher Name: $PUBLISHER"
 else
        PUBLISHER="Appcircle"
        printInfo "Publisher Name: $PUBLISHER"
 fi

createAndUploadAndroidLobApp $AndroidFileName "$AppName" "$PUBLISHER" "" "$UniqueName" "$VersionCode" "$Version"