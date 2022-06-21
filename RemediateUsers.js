/*!
     * Copyright 2017-2017 Mutual of Enumclaw. All Rights Reserved.
     * License: Public
*/ 

//Mutual of Enumclaw 
//
//Matthew Hengl and Jocelyn Borovich - 2019 :) :)
//
//Main file that controls remediation and notifications of all IAM User events. 
//Remediates actions when possible or necessary based on launch type and tagging. Then, notifies the user/security. 

//Make sure to that the master.invalid call does NOT have a ! infront of it
//Make sure to delete or comment out the change in the process.env.environtment

const AWS = require('aws-sdk');
AWS.config.update({region: process.env.region});
const iam = new AWS.IAM();
const epsagon = require('epsagon');
const Master = require("aws-automated-master-class/MasterClass").handler;
let path = require("aws-automated-master-class/MasterClass").path;
let master = new Master();
const sqs = new AWS.SQS();
const dynamodb = new AWS.DynamoDB();

let improperLaunch = false;

//Variables that allow these functions to be overridden in Jest testing by making the variable = jest.fn() 
//instead of its corresponding function
let callAutoTag = autoTag;
let callCheckTagsAndAddToTable = checkTagsAndAddToTable;
let callRemediate = remediate;
let callRemediateDynamo = remediateDynamo;

setSqsFunction = (value, funct) => {
   sqs[value] = funct;
};
setIamFunction = (value, funct) => {
   iam[value] = funct;
};

//**********************************************************************************************
//remediates a specific action after receiving an event log
async function handleEvent(event) {

   console.log(process.env.run);
   console.log(process.env.testEnv);
   console.log(JSON.stringify(event));

   path.p = 'Path: \nEntering handleEvent';
   
   //Start of one function
   if(master.checkDynamoDB(event)){
      
      let convertedEvent = master.dbConverter(event);
      console.log(convertedEvent);
      //Extra console.log statements for testing ===================================
      if (convertedEvent.ResourceName) {
         console.log(`"${convertedEvent.ResourceName}" is being inspected----------`);
      } else {
         console.log(`"${event.Records[0].dynamodb.Keys.ResourceName.S}" is being inspected----------`);
      }
      //==================================================
      if (convertedEvent.ResourceType == "User" && event.Records[0].eventName == 'REMOVE'){
         path.p += '\nEvent is of type User and has an event of REMOVE';
         try{
            let tags = await iam.listUserTags({UserName: convertedEvent.ResourceName}).promise();

            if (!(master.tagVerification(tags.Tags))) {
               path.p += '\nResource has the incorrect tags';
               await callRemediateDynamo(event, convertedEvent);
               await master.notifyUser(event, convertedEvent, 'User');
            }    
         }
         catch(e){
            console.log(e);
            path.p += '\nERROR';
            console.log(path.p);
            return e;
         }     
      } else {
         path.p += '\nEvent was not of type User and didn\'t have an event of REMOVE';
         //console.log('Remediation could not be performed, event didn\'t meet standards----------');
      }
      console.log(path.p);
      return;
   }
   //End of the function

   //Start of the function
   try{
      event = master.devTest(event);
      //Checks the event log for any previous errors. Stops the function if there is an error. 
      if (master.errorInLog(event)) {
         console.log(path.p);
         return; 
      }
      //End of the function
      
      console.log(`"${event.detail.requestParameters.userName}" is being inspected----------`);
      console.log(`Event action is ${event.detail.eventName}---------- `);
   
      //Conditionals to stop the function from continuing
      if (master.selfInvoked(event)) {
         console.log(path.p);
         return; 
      }   
      //Checks if the event is invalid. If it is invalid, then remediate. Else check for tags and add to the table with a TTL
      //if(master.checkKeyUser(event, 'userName')){
         //Delete the ! if there is one. Only use ! for testing.
         if(master.invalid(event)){
           improperLaunch = true;
           console.log('Calling notifyUser');
           await master.notifyUser(event, await callRemediate(event), 'User');
         //   if(event.detail.eventName == 'CreateUser' || event.detail.eventName == 'DeleteUser'){
         //       console.log('Event is either CreateUser or DeleteUser');
         //   }
           console.log(path.p);
           return;
         }
         if(event.detail.eventName == 'DeleteUser'){
            console.log('event is deleteUser');
           await master.notifyUser(event, await callRemediate(event), 'User');
         }else{
            await callCheckTagsAndAddToTable(event);
         }
         // delete path.p;
      //}
      //End of the function
      
   }catch(e){
      console.log(e);
      path.p += '\nERROR';
      console.log(path.p);
      return e;
   }
   console.log(path.p);
}

//Checks for and auto adds tags and then adds resource to the table if it is missing any other tags
async function checkTagsAndAddToTable(event){
   console.log('Entered checkTagsAndAddToTable');
   console.log(event);
   let params = {UserName: event.detail.requestParameters.userName};
   path.p += '\nEntering checkTagsAndAddToTable, Created params for function calls'; //Adds to the pathing
   try{
        path.p += '\nCalling AutoTag function'; //Adds to the pathing
        let tags = await callAutoTag(event, params); //Calls autoTag to auotmatically tag the resource that is coming through
         //As a parameter, also calls findId which will find the correct ID for the remediation to continue
        console.log(tags);
        //If statement to check if the correct tags are attached to the resource that is being inspected
        //Returns true if the resource as the wrong tags and returns false if the resource has the correct tags.
        if(!(master.tagVerification(tags.Tags))){
             //Calls a function in masterClass which will put the item in the DynamoDB table
             await master.putItemInTable(event, 'User', params.UserName);
             return true;
        }else{
             return false;
        }
   //Catch statement to catch an error if one were to appear in the try statement above
   }catch(e){
        console.log(e);
        path.p += '\nERROR';
        return e;
   }
}

//**********************************************************************************************
//Remediates the action performed and sends an email
async function remediate(event) {
   
   path.p += '\nEntered the remediation function';

   //Sets up required parameters
   const erp = event.detail.requestParameters;
   
   let params = {
      UserName: erp.userName
   };
   let results = await master.getResults(event, {});
   
   //Decides, based on the incoming event, which function to call to perform remediation
   try{
      switch(results.Action){
         case "AddUserToGroup":   
            path.p += '\nAddUserToGroup';
            params.GroupName = erp.groupName;
            await overrideFunction('removeUserFromGroup', params);
            results.ResourceName = erp.groupName;
            results.Response = "RemoveUserFromGroup";
         break;
         case "RemoveUserFromGroup":   
            path.p += '\nRemoveUserFromGroup';
            params.GroupName = erp.groupName;
            await  overrideFunction('addUserToGroup', params);
            results.ResourceName = erp.groupName;
            results.Response = "AddUserToGroup";
         break;
         case "PutUserPolicy":   
            path.p += '\nPutUserPolicy';
            params.PolicyName = erp.policyName;
            await  overrideFunction('deleteUserPolicy', params);
            results.ResourceName = erp.policyName;
            results.Response = "DeleteUserPolicy";
         break;
         case "AttachUserPolicy":
            path.p += '\nAttachUserPolicy';
            params.PolicyArn = erp.policyArn;
            await  overrideFunction('detachUserPolicy', params);
            results.ResourceName = erp.policyArn;
            results.Response = "DetachUserPolicy";
         break;
         case "DetachUserPolicy":
            path.p += '\nDetachUserPolicy';
            params.PolicyArn = erp.policyArn;
            await  overrideFunction('attachUserPolicy', params);
            results.ResourceName = erp.policyArn;
            results.Response = "AttachUserPolicy";
         break;
         case "DeleteUserPolicy": 
            path.p += '\nDeleteUserPolicy';
            results.ResourceName = erp.policyName;
            results.Response = "Remediation could not be performed";
         break;
         case "DeleteUser":
            path.p += '\nDeleteUser';
            results.Response = 'Remediation could not be performed';
            results.ResourceName = erp.userName;
            console.log('Checking to see if the resource is in the table');
            if(await master.checkTable(results.ResourceName, 'User')){
               path.p += '\nItem still in table';
               let tableParams = {
                  TableName: `remediation-db-table-${process.env.environment}-ShadowRealm`,
                  Key: {
                     'ResourceName': {
                        S: results.ResourceName
                     },
                     'ResourceType': {
                        S: 'User'
                     }
                  }
               }
               await dynamodb.deleteItem(tableParams).promise();
               path.p += '\nDeleted the item from the table';
            }
         break;
         case "CreateUser":
            path.p += '\nCreateUser';
            await callRemediateDynamo(event, results);
            results.Response = 'DeleteUser';
            results.Reason = 'Improper Launch';
         break;
      }
   }catch(e){
      console.log(e); 
      path.p += '\nERROR';
      return e;
   }
   results.Reason = 'Improper Tags';
   if(improperLaunch){
      results.Reason = `Improper Launch`;
   }
   if(results.Response == "Remediation could not be performed"){
      delete results.Reason;
   }
   path.p += '\nRemediation was finished';
   console.log(results);
   return results;
}


//**********************************************************************************************
//Function to remediate the event coming from DynamoDB. Remediates all attachments before removing the user
async function remediateDynamo(event, results){

   console.log('Entered remediateDynamo');

   path.p += '\nEntered RemediateDynamo';
   let params = {};
   if(results.KillTime){
      params = {UserName: results.ResourceName};
   }else{
      params = {UserName: event.detail.requestParameters.userName};
   }
   
   let count = 0;
   
   //lists the attachments
   let inline = {}; 
   let attached = {};
   let userInfo = {};
   console.log('Checking to see if the resource has an attached/inline policy or if the user is in a group');
   try {
      inline = await iam.listUserPolicies(params).promise(); 
      attached = await iam.listAttachedUserPolicies(params).promise(); 
      userInfo = await iam.listGroupsForUser(params).promise();
   } catch(e) {
      console.log(e); 
      path.p += '\nERROR';
      console.log("**************NoSuchEntity error caught**************");
      return e;
   }

   console.log("Checking to see if this user is in any groups.");
   console.log(userInfo.Groups.length);
   if(userInfo.Groups.length != 0){

      path.p += '\nDetaching users from groups';
      userInfo.Groups.forEach(async function(element) {
         params.GroupName = element.GroupName;
         path.p += `\nRemoving the user ${params.UserName} from the group ${params.GroupName}`;
         await overrideFunction('removeUserFromGroup', params);
         userInfo = await iam.listGroupsForUser(params).promise();
      });
      console.log("Done removing user from all groups.");
   }

   //checks if there is at least one attachment that needs remediation
   if (inline.PolicyNames[0] || attached.AttachedPolicies[0]) {

      let newEvent = event;
      if(results.KillTime){
         path.p += '\nEvent is a DynamoDB event and There are inline and attached policies';
         let requestParameters = {
            userName: params.UserName,
            policyName: '',
            policyArn: '' 
         };
         newEvent = master.translateDynamoToCloudwatchEvent(event, requestParameters);
      }
      //Remediates all the inline policies
      if (inline.PolicyNames[0]) {

         path.p += '\nRemediating inline policies';
         for (let i = 0; i < inline.PolicyNames.length; i++) {
            newEvent.detail.requestParameters.policyName = inline.PolicyNames[i];
            newEvent.detail.eventName = 'PutUserPolicy';
            await callRemediate(newEvent);
         }
      }
      //Remediates all the attached policies
      if (attached.AttachedPolicies[0]) {

         path.p += '\nRemediating attached policies';
         for (let i = 0; i < attached.AttachedPolicies.length; i++) {
            newEvent.detail.requestParameters.policyArn = attached.AttachedPolicies[i].PolicyArn;
            newEvent.detail.eventName = 'AttachUserPolicy';
            await callRemediate(newEvent);
         }   
      }
   }

   if (!results.KillTime && count != 0) { 
      dbStopper.c = count;
   }

   if(results.KillTime){
      event.Records[0].dynamodb.OldImage.action = 'CreateUser';
   }else{
      event.detail.eventName = "CreateUser";
   }
   
   if(!results.KillTime){
      if(!(master.snd()) && master.isConsole(event)){
         path.p += '\nCreating SQS message';
         if(process.env.testEnv == 'dev'){
            process.env.environment = 'snd';
         }
         let sqsParams = {
            MessageBody: JSON.stringify(event),
            QueueUrl: `${process.env.QueueUrl}`,
            DelaySeconds: 10,
         };
         // if(process.env.run == 'false'){
         //    //When not testing - delete the override statement. Only used for testing purposes
         //    await setSqsFunction('sendMessage', (params) => {
         //       console.log('Overriding sendMessage');
         //       return {promise: () => {}};
         //    });
         // }
         await sqs.sendMessage(sqsParams).promise();
         path.p += '\nSent SQS message';
         console.log("Message sent to SQS");
      }
   }

   //Deletes the user
   path.p += '\nFinished remediation of policies';
   delete params.GroupName;
   try{
      console.log('Checking to see if the user was created using an Access Key or Login Profile');
      let AK = await iam.listAccessKeys(params).promise();
      console.log(AK);
      AK.AccessKeyMetadata.push({});
      if(AK.AccessKeyMetadata[0].AccessKeyId){
         console.log('Was created using an Access Key');
         params.AccessKeyId = AK.AccessKeyMetadata[0].AccessKeyId;
         await overrideFunction('deleteAccessKey', params);
         path.p += '\nDeleted the Access Key';
         delete params.AccessKeyId;
      }else{
         console.log('Was created using a login profile');
         await overrideFunction('deleteLoginProfile', params);
         path.p += '\nLogin Profile was deleted.';
      }
   }catch(e){
      throw e;
   }
   await overrideFunction('deleteUser', params);
   path.p += `\n${params.UserName} was deleted`;
   // await master.notifyUser(event, results, 'User');
   return results;
}


//**********************************************************************************************
//Automatically adds missing tags, TechOwner and Environment, if needed 
async function autoTag(event, params) {

   let tags = await iam.listUserTags(params).promise(); //There was an error here.

   //checks if env is sandbox AND checks for and adds TechOwner tag
   if (master.snd() && master.needsTag(tags.Tags, `${process.env.tag3}`)){
      
      //Adds the TechOwner tag to the resource
      await iam.tagUser(await master.getParamsForAddingTags(event, params, `${process.env.tag3}`)).promise();
      tags = await iam.listUserTags(params).promise();
      path.p += `\nAdding ${process.env.tag3} to resource`;
   }
   
   //checks if the resource has an environment tag and adds it if it doesn't
   if (master.needsTag(tags.Tags, 'Environment')) {
      
      //Adds the Environment tag to the resource
      await iam.tagUser(await master.getParamsForAddingTags(event, params, 'Environment')).promise();
      tags = await iam.listUserTags(params).promise();
      path.p += '\nAdding Environment to resource';
   }
   return tags;
};

async function overrideFunction(apiFunction, params){
   if(process.env.run == 'false'){
      epsagon.label('remediate','true');
      await setIamFunction(apiFunction, (params) => {
         console.log(`Overriding ${apiFunction}`);
         return {promise: () => {}};
     });
   }
   await iam[apiFunction](params).promise();
};


exports.handler = handleEvent;
exports.checkTagsAndAddToTable = checkTagsAndAddToTable; 
exports.remediateDynamo = remediateDynamo;
exports.autoTag = autoTag;
exports.remediate = remediate;

//overrides the given function (only for jest testing)
exports.setIamFunction = (value, funct) => {
   iam[value] = funct;
};

exports.setAutoTag = (funct) => {
   callAutoTag = funct;
};

exports.setRemediate = (funct) => {
   callRemediate = funct;
};

exports.setRemediateDynamo = (funct) => {
   callRemediateDynamo = funct;
};

exports.setCheckTagsAndAddToTable = (funct) => {
   callCheckTagsAndAddToTable = funct;
};
exports.setSqsFunction = (value, funct) => {
   sqs[value] = funct;
};

exports.setDBFunction = (value, funct) => {
   dynamodb[value] = funct;
};

//Created by Matthew Hengl and Jocelyn Borovich. Ur fav 2019 interns!! :) :)
