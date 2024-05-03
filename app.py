import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from Classe_Highbond.Highbond_API_Class import hbapi


tkhb = st.text_input(label="Insira seu token de API do Diligent One", type='password')
org_id = st.text_input('Informe o ID da organização:')
choose_server = st.selectbox('Escolha o servidor de API do Diligent One:', options=['EUA', 'Canadá', 'Europa', 'Ásia', 'Oceania', 'África', 'América do Sul', 'US Feds', 'US States'])

if choose_server == 'EUA':
    server = 'apis-us.highbond.com'
elif choose_server == 'Canadá': 
    server = 'apis-ca.highbond.com'
elif choose_server == 'Europa':
    server = 'apis-eu.highbond.com'
elif choose_server == 'Ásia':
    server = 'apis-ap.highbond.com'
elif choose_server == 'Oceania':
    server = 'apis-au.highbond.com'
elif choose_server == 'África':
    server = 'apis-af.highbond.com'
elif choose_server == 'América do Sul':
    server = 'apis-sa.highbond.com'
elif choose_server == 'US Feds':
    server = 'apis.highbond-gov.com'
elif choose_server == 'US States':
    server = 'apis.highbond-gov2.com'
else:
    server = 'apis-us.highbond.com'

def connect_hb():
    ihb = hbapi(token=tkhb, organization_id=org_id, server=server, talkative=True)
    return ihb

button = st.button('Iniciar a tabela!')
if button:
    try:
        if not bool(tkhb):
            raise Exception("O token não foi preenchido!")
        elif not bool(org_id):
            raise Exception("O id da organização não foi preenchido!")

        ihb = connect_hb()
        jsonRobots = ihb.getRobots()
        dfRobots = pd.json_normalize(jsonRobots['data'])

        liCategories = dfRobots['attributes.category'].drop_duplicates().tolist()
        
        dfCount = dfRobots.groupby('attributes.category').count()
        
        # labels = liCategories
        labels = dfCount.index.tolist()
        size = dfCount['id'].tolist()

        pieChart, ax1 = plt.subplots()

        ax1.pie(size, labels=labels, autopct='%1.1f%%', startangle=90)
        ax1.axis('equal')

        st.markdown("### Robôs Disponíveis:")
        st.dataframe(dfRobots)
        st.markdown('### Quantidade de Robôs por Categoria:')
        st.pyplot(pieChart)
    except Exception as e:
        st.text(f'Não foi possível montar as tabelas devido ao seguinte problema:\n\n{e}')
