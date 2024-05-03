from Classe_Highbond.Highbond_API_Class import hbapi
import pandas as pd
import matplotlib.pyplot as plt

token = '916dc0b9ef80720934afb8a4479cb9c29384daedd1191c5f7774f89e7f56c358'
ihb = hbapi(token = token, organization_id= '3065', server='apis-us.highbond.com')

jsonRobots = ihb.getRobots()['data']
dfRobots = pd.json_normalize(jsonRobots)
# print(dfRobots['attributes.category'])

liCategories = dfRobots['attributes.category'].drop_duplicates().tolist()
# print(f'categorias: {liCategories}')

dfCount = dfRobots.groupby('attributes.category').count()

labels = liCategories
size = dfCount['id'].tolist()

pieChart, ax1 = plt.subplots()

ax1.pie(size, labels=labels, autopct='%1.1f%%', startangle=90)
ax1.axis('equal')

