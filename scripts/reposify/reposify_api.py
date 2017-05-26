import requests
import simplejson

def api_request(key, function, params=None, data=None, base_url='https://api.reposify.com', method='get', retries=1):
    """General-purpose function to create web requests to REPOSIFY.
    
    Arguments:
        function  -- name of the function you want to execute
        params    -- dictionary of parameters for the function
    
    Returns
        A dictionary containing the function's results.
    
    """
    # Add the API key parameter automatically
    params['token'] = key

    # Send the request
    tries = 0
    error = False
    while tries <= retries:
        try:
            if method.lower() == 'post':
                data = requests.post(base_url + function, simplejson.dumps(data), params=params, headers={'content-type': 'application/json'})
            elif method.lower() == 'delete':
                data = requests.delete(base_url + function, params=params)
            else:
                data = requests.get(base_url + function, params=params)

            # Exit out of the loop
            break
        except:
            error = True
            tries += 1

    if error and tries >= retries:
        raise APIError('Unable to connect to Reposify')

    # Check that the API key wasn't rejected
    if data.status_code == 401:
        try:
            raise APIError(data.json()['error'])
        except:
            pass
        raise APIError('Invalid API key')
    
    # Parse the text into JSON
    try:
        data = data.json()
    except:
        raise APIError('Unable to parse JSON response')
    
    # Raise an exception if an error occurred
    if type(data) == dict and data.get('error', None):
        raise APIError(data['error'])
    
    # Return the data
    return data

def reposify_search(key, banner, filters, page):
    params = {'page' : page }
    if banner is not None:
        params['banner'] = banner
    if filters is not None:
        params['filters'] = filters
    res = api_request(key, '/v1/insights/search', params, None, 'https://api.reposify.com', 'get', 1)
    return res