import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from Classe_Highbond.Highbond_API_Class import hbapi


st.set_page_config(page_title='Consulta de Robôs',  layout='wide', page_icon=':robot:')

def connect_hb():
    ihb = hbapi(token=tkhb, organization_id=org_id, server=server, talkative=True)
    return ihb
    
expander1 = st.expander("Parâmetros de Consulta", expanded=True)

with expander1:
    tkhb = st.text_input(label="Insira seu token de API do Diligent One", type='password')
    org_id = st.text_input('Informe o ID da organização:')
    choose_server = st.selectbox('Escolha o servidor de API do Diligent One:', options=['EUA', 'Canadá', 'Europa', 'Ásia', 'Oceania', 'África', 'América do Sul', 'US Feds', 'US States'])

dfServers = pd.read_csv('refs/servers.csv')

dfServers = pd.read_csv('refs/servers.csv')
filter = dfServers['name'] == choose_server
server = dfServers[filter]['server'].iloc[0]

button = st.button('Gerar Dashboard!')
if button:
    try:
        if not bool(tkhb):
            raise Exception("O token não foi preenchido!")
        elif not bool(org_id):
            raise Exception("O id da organização não foi preenchido!")

        ihb = connect_hb()
        jsonRobots = ihb.getRobots()
        dfRobots = pd.json_normalize(jsonRobots['data'])
        
        dfCount = dfRobots.groupby('attributes.category').count()
        
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
