"""
Showcase the different actions we can perform via the Splunk app on Enterprise security generated notables. 

- Updates the notable status, owner, comment, criticality
- Triggers risk modifier for sourceAddress
- Triggers risk modifier for sourceUserName


Inputs: ES notable from saved search
Required artifact fields: event_id, sourceAddress, sourceUserName
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Update_Notable' block
    Update_Notable(container=container)

    return

def Update_Notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Update_Notable() called')

    # collect data for 'Update_Notable' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.event_id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Update_Notable' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'owner': "admin",
                'status': "in progress",
                'event_id': container_item[0],
                'urgency': "high",
                'comment': "Phantom investigating",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("update event", parameters=parameters, assets=['splunkdemo'], callback=Update_Notable_callback, name="Update_Notable")

    return

def Update_Notable_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Update_Notable_callback() called')
    
    Get_hosts(action=action, success=success, container=container, results=results, handle=handle)
    Prepare_risk_query_User(action=action, success=success, container=container, results=results, handle=handle)
    Prepare_risk_query_source(action=action, success=success, container=container, results=results, handle=handle)

    return

def Get_hosts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Get_hosts() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_hosts' call

    parameters = []
    
    # build parameters list for 'Get_hosts' call
    parameters.append({
        'query': "| from datamodel:Authentication.Failed_Authentication|search *|fields user, src",
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunkdemo'], name="Get_hosts", parent_action=action)

    return

def Update_risk_object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Update_risk_object() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_risk_object' call
    formatted_data_1 = phantom.get_format_data(name='Prepare_risk_query_User')

    parameters = []
    
    # build parameters list for 'Update_risk_object' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunkdemo'], name="Update_risk_object")

    return

def Prepare_risk_query_User(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Prepare_risk_query_User() called')
    
    template = """| makeresults | eval user=\"{0}\" |eval description=\"Phantom\"| sendalert risk param._risk_object=\"user\" param._risk_object_type=\"system\" param._risk_score=166"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceUserName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Prepare_risk_query_User")

    Update_risk_object(container=container)

    return

def Prepare_risk_query_source(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Prepare_risk_query_source() called')
    
    template = """| makeresults | eval source=\"{0}\" |eval description=\"Phantom\"| sendalert risk param._risk_object=\"source\" param._risk_object_type=\"system\" param._risk_score=10"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Prepare_risk_query_source")

    Update_risk_source(container=container)

    return

def Update_risk_source(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Update_risk_source() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_risk_source' call
    formatted_data_1 = phantom.get_format_data(name='Prepare_risk_query_source')

    parameters = []
    
    # build parameters list for 'Update_risk_source' call
    parameters.append({
        'query': formatted_data_1,
        'display': "",
    })

    phantom.act("run query", parameters=parameters, assets=['splunkdemo'], name="Update_risk_source")

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
