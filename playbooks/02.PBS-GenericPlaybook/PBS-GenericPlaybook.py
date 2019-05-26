"""
This playbook shows how we can collect indicators in a more generic way. As long as the container artifacts use CEF Compatible fields to store indicators , this playbook will collect IPs, Domains, URLs and Hashes. 

It will then run related actions on any asset which supports such actions.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'AllContainerArtifacts' block
    AllContainerArtifacts(container=container)

    return

def AllContainerArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('AllContainerArtifacts() called')
    input_parameter_0 = ""

    AllContainerArtifacts__results_hash = None
    AllContainerArtifacts__results_ip = None
    AllContainerArtifacts__results_url = None
    AllContainerArtifacts__results_domain = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Get all artifacts containing hash type
    collected_artifacts = phantom.collect_from_contains(container=container, contains=["hash"])
    parameters = list()    

    for item in collected_artifacts:
        if item != "":        
            parameters.append({
                'hash': item
            })   
    
    phantom.debug(parameters)

    AllContainerArtifacts__results_hash = parameters
    
    # Get all artifacts containing ip type
    collected_artifacts = phantom.collect_from_contains(container=container, contains=["ip"])
    parameters = list()    

    for item in collected_artifacts:
        if item != "":        
            parameters.append({
                'ip': item
            })   
    
    phantom.debug(parameters)

    AllContainerArtifacts__results_ip = parameters    

    # Get all artifacts containing url type
    collected_artifacts = phantom.collect_from_contains(container=container, contains=["url"])
    parameters = list()    

    for item in collected_artifacts:
        if item != "":
            parameters.append({
                'url': item
            })   
    
    phantom.debug(parameters)

    AllContainerArtifacts__results_url = parameters  
    
    # Get all artifacts containing domain type
    collected_artifacts = phantom.collect_from_contains(container=container, contains=["domain"])
    parameters = list()    

    for item in collected_artifacts:
        if item != "":        
            parameters.append({
                'domain': item
            })   
    
    phantom.debug(parameters)

    AllContainerArtifacts__results_domain = parameters      
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='AllContainerArtifacts:results_hash', value=json.dumps(AllContainerArtifacts__results_hash))
    phantom.save_run_data(key='AllContainerArtifacts:results_ip', value=json.dumps(AllContainerArtifacts__results_ip))
    phantom.save_run_data(key='AllContainerArtifacts:results_url', value=json.dumps(AllContainerArtifacts__results_url))
    phantom.save_run_data(key='AllContainerArtifacts:results_domain', value=json.dumps(AllContainerArtifacts__results_domain))
    file_reputation_6(container=container)
    lookup_domain_1(container=container)
    url_reputation_1(container=container)

    return

def file_reputation_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_6() called')

    AllContainerArtifacts__results_hash = json.loads(phantom.get_run_data(key='AllContainerArtifacts:results_hash'))
    # collect data for 'file_reputation_6' call
    phantom.debug(AllContainerArtifacts__results_hash)

    if len(AllContainerArtifacts__results_hash) > 0:
        parameters = AllContainerArtifacts__results_hash

        phantom.act("file reputation", parameters=parameters, callback=join_Initial_filtering, name="file_reputation_6")

    return

def lookup_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('lookup_domain_1() called')

    AllContainerArtifacts__results_domain = json.loads(phantom.get_run_data(key='AllContainerArtifacts:results_domain'))
    # collect data for 'lookup_domain_1' call

    if len(AllContainerArtifacts__results_domain) > 0:
        parameters = AllContainerArtifacts__results_domain

        phantom.act("lookup domain", parameters=parameters, callback=join_Initial_filtering, name="lookup_domain_1")
    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    AllContainerArtifacts__results_url = json.loads(phantom.get_run_data(key='AllContainerArtifacts:results_url'))
    # collect data for 'lookup_domain_1' call

    if len(AllContainerArtifacts__results_url) > 0:
        parameters = AllContainerArtifacts__results_url

        phantom.act("url reputation", parameters=parameters, callback=join_Initial_filtering, name="url_reputation_1")
    return

def Initial_filtering(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Initial_filtering() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.status", "==", "failed"],
            ["file_reputation_6:action_result.status", "==", "failed"],
            ["lookup_domain_1:action_result.status", "==", "failed"],
        ],
        logical_operator='or',
        name="Initial_filtering:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Summary_function_Fail(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_6:action_result.status", "==", "success"],
            ["lookup_domain_1:action_result.status", "==", "success"],
            ["url_reputation_1:action_result.status", "==", "success"],
        ],
        logical_operator='or',
        name="Initial_filtering:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Summary_function_Success(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def join_Initial_filtering(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_Initial_filtering() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'file_reputation_6', 'lookup_domain_1', 'url_reputation_1' ]):
        
        # call connected block "Initial_filtering"
        Initial_filtering(container=container, handle=handle)
    
    return

def Summary_function_Success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Summary_function_Success() called')
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:Initial_filtering:condition_2:url_reputation_1:action_result.parameter.url"])
    filtered_results_data_2 = phantom.collect2(container=container, datapath=["filtered-data:Initial_filtering:condition_2:lookup_domain_1:action_result.parameter.domain"])
    filtered_results_data_3 = phantom.collect2(container=container, datapath=["filtered-data:Initial_filtering:condition_2:file_reputation_6:action_result.parameter.hash"])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]
    filtered_results_item_2_0 = [item[0] for item in filtered_results_data_2]
    filtered_results_item_3_0 = [item[0] for item in filtered_results_data_3]

    Summary_function_Success__total_success_artifacts = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(filtered_results_item_1_0)
    phantom.debug(filtered_results_item_2_0)
    phantom.debug(filtered_results_item_3_0)    
    Summary_function_Success__total_success_artifacts = len(filtered_results_item_1_0) + len(filtered_results_item_2_0) + len(filtered_results_item_3_0)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Summary_function_Success:total_success_artifacts', value=json.dumps(Summary_function_Success__total_success_artifacts))
    pin_2(container=container)

    return

def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_2() called')

    Summary_function_Success__total_success_artifacts = json.loads(phantom.get_run_data(key='Summary_function_Success:total_success_artifacts'))

    phantom.pin(container=container, message="Success Artifacts", data=Summary_function_Success__total_success_artifacts, pin_type="card_medium", pin_style="blue", name=None)

    return

def Summary_function_Fail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Summary_function_Fail() called')
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:Initial_filtering:condition_1:lookup_domain_1:action_result.parameter.domain"])
    filtered_results_data_2 = phantom.collect2(container=container, datapath=["filtered-data:Initial_filtering:condition_1:file_reputation_6:action_result.parameter.hash"])
    filtered_results_data_3 = phantom.collect2(container=container, datapath=["filtered-data:Initial_filtering:condition_1:url_reputation_1:action_result.parameter.url"])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]
    filtered_results_item_2_0 = [item[0] for item in filtered_results_data_2]
    filtered_results_item_3_0 = [item[0] for item in filtered_results_data_3]

    Summary_function_Fail__total_failed_artifacts = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(filtered_results_item_1_0)
    phantom.debug(filtered_results_item_2_0)
    phantom.debug(filtered_results_item_3_0)    
    Summary_function_Fail__total_failed_artifacts = len(filtered_results_item_1_0) + len(filtered_results_item_2_0) + len(filtered_results_item_3_0)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Summary_function_Fail:total_failed_artifacts', value=json.dumps(Summary_function_Fail__total_failed_artifacts))
    pin_3(container=container)

    return

def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_3() called')

    Summary_function_Fail__total_failed_artifacts = json.loads(phantom.get_run_data(key='Summary_function_Fail:total_failed_artifacts'))

    phantom.pin(container=container, message="Failed artifacts", data=Summary_function_Fail__total_failed_artifacts, pin_type="card_medium", pin_style="red", name=None)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return