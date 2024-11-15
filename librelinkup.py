#!/usr/bin/env python
# coding: utf-8

import requests
import json
import time
from datetime import datetime,timedelta
import pytz
import os

# For encoding and decoding
import jwt
import hashlib

DEBUG = False

# Defining some headers
# -----------

def getNightscoutHeaders(settings) :
    return {
        'api-secret': settings['nightscout_secret'],
        'User-Agent': 'FreeStyle LibreLink Up NightScout Uploader',
        'Content-Type': 'application/json',
    }


def getLibreHeader(token=None) :

    header = {
        'version': '4.12.0', #'4.7.0', # 4.2.1 ? 4.5.0 ? 4.2.2 ?
        'product': 'llu.ios',
        #
        # Used for debugging, but none of it helped:
        #
        #'accept-encoding': 'gzip, deflate, br',
        #'accept':'application/json',
        #'cache-control': 'no-cache',
        #'connection': 'Keep-Alive',
        #'content-type': 'application/json',
        #'user-agent':'kurt',
    }

    if token :
        header['authorization'] = 'Bearer '+token

        # Need to include a hashed account-id in the header.
        # See https://github.com/timoschlueter/nightscout-librelink-up/pull/170
        #
        decoded_token = jwt.decode(token,options={'verify_signature':False})
        if DEBUG:
            print('decoded token:',decoded_token)
        hashed_id = hashlib.sha256(decoded_token['id'].encode()).hexdigest()
        header['account-id'] = hashed_id

    return header


# Get Libre Linkup Auth Ticket
# ---------

def check_or_renew_auth(current_authToken,current_expires,settings) :

    TIME_FORMAT='%Y-%m-%d %H:%M:%S'

    # Get a new auth token if the old one expired.
    if datetime.now() > datetime.utcfromtimestamp(current_expires) :

        if DEBUG :
            print('Creating new auth ticket')
        api_endpoint = settings['api_endpoint']
        auth_url = 'https://api-{}.libreview.io/llu/auth/login'.format(api_endpoint)
        json_input = {'email':settings['libre_email'],
                      'password':settings['libre_password']}

        r = requests.post(auth_url,
                          json=json_input,
                          headers=getLibreHeader(),
                          allow_redirects=True)
    
        content = json.loads(r.content)
        if DEBUG :
            print(content)
        new_authToken = content['data']['authTicket']['token']
        new_expires = content['data']['authTicket']['expires']

        if DEBUG :
            print('New auth ticket:',content['data']['authTicket'])
            print('Expires:',datetime.utcfromtimestamp(new_expires).strftime(TIME_FORMAT))
        
        return new_authToken, new_expires

    # If the old auth token is still valid, keep it.
    if DEBUG :
        print('Reusing old auth ticket.')
        print('Time right now is:   {}'.format(datetime.now().strftime(TIME_FORMAT)))
        print('Auth ticket expires: {}'.format(datetime.utcfromtimestamp(current_expires).strftime(TIME_FORMAT)))

    return current_authToken, current_expires

# Get patient ID
# -------
# Some intermediate step apparently just to get the patient id.

def get_patientId(token,settings) :

    url = 'https://api-{}.libreview.io/llu/connections'.format(settings['api_endpoint'])
    r = requests.get(url,headers=getLibreHeader(token))
    
    patientId = json.loads(r.content)['data'][0]['patientId']
    
    return patientId

def get_inst_value(token,settings) :

    url = 'https://api-{}.libreview.io/llu/connections'.format(settings['api_endpoint'])
    r = requests.get(url,headers=getLibreHeader(token))
    
    r_content = json.loads(r.content)
    if DEBUG :
        print('Status code:',r.status_code)
        print('r_content:')
        print(r_content)
        print('r_content end.:')

    if 'data' not in r_content.keys() :
        raise RuntimeError('Something went wrong. Exiting.')

    glucoseMeasurement = r_content['data'][0]['glucoseMeasurement']
    
    return glucoseMeasurement


# Get Libre Data, format for NS, upload.
# ---------

def graph_call(patientId,token,settings) :

    url = 'https://api-{}.libreview.io/llu/connections/{}/graph'
    url = url.format(settings['api_endpoint'],patient_id)

    r = requests.get(url,headers=getLibreHeader(token))

    data = json.loads(r.content)['data']

    return data


def libre_trend_int_to_string(the_int) :
    return {5:'SingleUp',
            4:'FortyFiveUp',
            3:'Flat',
            2:'FortyFiveDown',
            1:'SingleDown',}.get(the_int,'NOT COMPUTABLE')


def nightscout_last_entry_time_ms(settings) :
    url = '{}://{}/api/v1/entries?count=1'.format(settings['protocol'],settings['nightscout_url'])
    r = requests.get(url,headers=getNightscoutHeaders(settings),allow_redirects=True)
    if not r.text :
        return 0
    if DEBUG :
        print(r.text)
    return int(r.text.split('\t')[1])


def upload_to_nightscout(ns_data_point,settings) :
    url = '{}://{}/api/v1/entries'.format(settings['protocol'],settings['nightscout_url'])
    r = requests.post(url, json=[ns_data_point],headers=getNightscoutHeaders(settings),allow_redirects=True)
    if DEBUG :
        print(r.text)
    return


def delete_old_nightscout(settings,hours=6.0) :
    timestr = (datetime.now() - timedelta(hours=hours)).astimezone(pytz.utc).replace(tzinfo=None).isoformat(timespec='milliseconds')+'Z'

    url = '{}://{}/api/v1/entries?find[dateString][$lte]={}'
    url = url.format(settings['protocol'],settings['nightscout_url'],timestr)

    r = requests.delete(url,headers=getNightscoutHeaders(settings),allow_redirects=True)
    #print(r.text)
    return


def main() :
    
    if not os.path.exists('user_settings.txt') :
        print('Error! user_settings.txt missing!')
        return 1

    user_settings = {}
    with open('user_settings.txt') as f :
        for line in f :
            tmp = line.split(':')
            user_settings[tmp[0].strip()] = tmp[-1].strip()


    existing_authToken = ''
    existing_expires = 0

    if os.path.exists('token.txt') :
        with open('token.txt') as f :
            for line in f :
                if 'token' in line :
                    existing_authToken = line.split('token:')[-1].strip()
                if 'expires' in line :
                    existing_expires = int(line.split('expires:')[-1].strip())

    authToken,expires = check_or_renew_auth(existing_authToken,existing_expires,user_settings)

    if authToken != existing_authToken :
        with open('token.txt','w') as f :
            f.write('token: {}\n'.format(authToken))
            f.write('expires: {}\n'.format(expires))

    tz_libre = pytz.timezone(user_settings['timezone'])

    #data = graph_call(patientId,authToken,user_settings)
    #meas = data['connection']['glucoseMeasurement']

    meas = get_inst_value(authToken,user_settings)

    dt_libretz = tz_libre.localize( datetime.strptime(meas['Timestamp'],'%m/%d/%Y %I:%M:%S %p') )
    dt_utc = dt_libretz.astimezone(pytz.utc)
    entry_timestamp = int(dt_utc.timestamp()*1000.)
    
    ns_lastentry_t = nightscout_last_entry_time_ms(user_settings)

    if DEBUG :
        print(entry_timestamp,ns_lastentry_t)
    if (entry_timestamp <= ns_lastentry_t) :
        # do not update!
        return
    
    inst_ns = {'type':'sgv',
               'dateString':dt_utc.replace(tzinfo=None).isoformat(timespec='milliseconds')+'Z',
               'date':entry_timestamp,
               'sgv':int(meas['ValueInMgPerDl']),
               'device':'timoschlueter',
               'direction':libre_trend_int_to_string(meas['TrendArrow'])
              }

    if DEBUG:
        print('Submitting:',inst_ns)


    upload_to_nightscout(inst_ns,user_settings)
    #delete_old_nightscout(user_settings)

    return

if __name__ == '__main__':
    main()
