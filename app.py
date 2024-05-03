import streamlit as st
import pandas as pd
import requests as rq
from Classe_Highbond.Highbond_API_Class import hbapi


tkhb = st.text_input(label="Insira seu token", type='password')
org_id = st.text_input('Informe o ID da organização:')
server = st.selectbox('Escolha o servidor:', options=['apis-us.highbond.com', 'apis-ca.highbond.com', 'apis-eu.highbond.com', 'apis-ap.highbond.com', 'apis-au.highbond.com', 'apis-af.highbond.com', 'apis-sa.highbond.com', 'apis.highbond-gov.com', 'apis.highbond-gov2.com'])

def load_table():
    ihb = hbapi(token=tkhb, organization_id=org_id, server=server, talkative=True)
    jsonRobots = ihb.getRobots()
    dfRobots = pd.json_normalize(jsonRobots['data'])
    return dfRobots

button = st.button('Iniciar a tabela!')
if button:
    st.text("# Robôs Disponíveis:")
    st.dataframe(load_table())
