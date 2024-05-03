import requests as rq
import pathlib as pl
import os
import base64

from typing import Literal, List, Union
# import pandas as pd

class hbapi:

    def __init__(self, token: str,
                 organization_id: str, 
                 server: Literal['apis-us.highbond.com', 'apis-ca.highbond.com', 'apis-eu.highbond.com', 'apis-ap.highbond.com', 'apis-au.highbond.com', 'apis-af.highbond.com', 'apis-sa.highbond.com', 'apis.highbond-gov.com', 'apis.highbond-gov2.com'] = 'apis-us.highbond.com', 
                 talkative: bool = True):
        """
        ________________________________________________________________________
        Cria uma instância da classe hbapi para interação simplificada com a API Highbond.

        #### Referência: 
        - https://docs-apis.highbond.com/

        #### Parâmetros:
        - token (str): Token do Highbond obtido através do portal.
        - organization_id (str): ID da organização, coletado da URL do portal ao logar.
        - server (str): Servidor do Highbond a ser utilizado. Padrão é 'apis-us.highbond.com'.
        - talkative (bool): Se True, exibe mensagens de sucesso em requisições. Padrão é True.

        #### Opções disponíveis de servidor:
        - Estados Unidos da América: https://apis-us.highbond.com
        - Canadá: https://apis-ca.highbond.com
        - Europa: https://apis-eu.highbond.com
        - Ásia: https://apis-ap.highbond.com
        - Oceania: https://apis-au.highbond.com
        - África: https://apis-af.highbond.com
        - América do Sul: https://apis-sa.highbond.com
        - Governo Federal dos EUA: https://apis.highbond-gov.com
        - Governo Estadual dos EUA: https://apis.highbond-gov2.com
        """
        # CONFIGURAÇÕES DA CLASSE
        self.token = token
        self.organization_id = organization_id
        self.server = server
        self.talkative = talkative

# Robots Agents
    def getAgents(self) -> dict:
        """
        Lista os agentes do robotics instalados na organização

        #### Referência:
        https://docs-apis.highbond.com/#operation/getAgents

        #### Retorna:
        Um dicionário contendo informações sobre os agentes do robôs.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getAgents()
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os agentes do robôs.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/agents'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, headers=apiHeaders)
            
            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception('Falha desconhecida.')

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

# Robots
    def getRobots(self) -> dict:
        """
        Lista os robôs disponíveis no robotics

        #### Referência:
        https://docs-apis.highbond.com/#operation/getRobots

        #### Retorna:
        Um dicionário contendo informações sobre os robôs.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getRobots()
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception('Falha desconhecida.')

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def createRobot(self, robot_name: str, robot_description: str = None, robot_category: Literal['acl', 'highbond', 'workflow'] = 'acl') -> dict:
        """
        Cria um robô na organização

        #### Referência:
        https://docs-apis.highbond.com/#operation/createRobot

        #### Parâmetros:
        - robot_name (str): O nome do robô ACL que será criado.
        - robot_description (str): A descrição do robô.
        - robot_category (str): O topo de robô que será criado, padrão é 'acl'

        #### Retorna:
        Um dict com informações sobre o robô criado.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.createRobot('nome_robô', 'descricao_robo', 'acl')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'name': robot_name,
            'description': robot_description,
            'category': robot_category
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.post(url, params=qParameters, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def putRobot(self, robot_id, robot_new_name: str, robot_new_description: str, robot_new_category: Literal['acl', 'highbond', 'workflow']) -> dict:
        """
        Atualiza as informações de um robô

        #### Referência:
        https://docs-apis.highbond.com/#operation/putRobot

        #### Parâmetros:
        - robot_id (str): O ID do robô cujos dados serão alterados.
        - robot_new_name (str): O novo nome do robô (manter o mesmo caso não queira trocar).
        - robot_new_description (str): A nova descrição do robô (manter o mesmo caso não queira trocar)
        - robot_new_category (str): A nova categoria do robô (manter a mesma caso não queira trocar)

        #### Retorna:
        Um dicionário contendo informações sobre as alterações feitas no robô.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.putRobot('novo_nome', 'nova_descricao', 'acl')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'id': robot_id,
            'name': robot_new_name,
            'description': robot_new_description,
            'category': robot_new_category
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}'

        # AÇÃO E RESPOSTA
        try:            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.put(url, params=qParameters, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def deleteRobot(self, robot_id: str) -> dict:
        """
        Deleta um robô e todas as tarefas associadas a ele

        #### Referência:
        https://docs-apis.highbond.com/#operation/deleteRobot

        #### Parâmetros:
        - robot_id (str): O ID do robô que será deletado.
        
        #### Retorna:
        Um dicionário contendo informações sobre o robô deletado.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.deleteRobot('12345')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os arquivos do robô.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server

        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.delete(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

# Robot Tasks
    def getRobotTasks(self, robot_id: str, environment: str) -> dict:
        """
        Lista as tarefas de um robô ACL.

        #### Referência: 
        https://docs-apis.highbond.com/#operation/getRobotTasks

        #### Parâmetros:
        - robot_id (str): O ID do robô ACL onde as tarefas estão armazenadas.
        - environment (str): O ambiente onde as tarefas estão armazenadas. Pode ser 'production' para o ambiente de produção ou 'development' para o ambiente de desenvolvimento.

        #### Retorna:
        Um dicionário contendo informações sobre as tarefas do robô.

        #### Exceções:
        - Raises Exception se o ambiente não estiver definido corretamente.
        - Raises Exception se a requisição API falhar com códigos de status diferentes de 200.
        - Raises Exception se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='sua_organizacao')
        result = instance.getRobotTasks(robot_id='123', environment='production')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo informações sobre as tarefas do robô.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'env': environment
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}/robot_tasks'

        # AÇÃO E RESPOSTA
        try:
            if not ((environment == 'production') or (environment == 'development')):
                raise Exception('O ambiente não foi definido corretamente.')
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, params=qParameters, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json)
            
        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def createRobotTask(self, robot_id, environment: Literal['production', 'development'], 
                        task_name, app_version: int = None, emails_enabled: bool = False, 
                        log_enabled: bool = False, pw_crypto_key: str = None, 
                        share_encrypted: bool = False, analytic_names: list = None) -> dict:
        """
        Cria uma tarefa em um robô do Highbond, e em um ambiente específico

        #### Referência:
        https://docs-apis.highbond.com/#operation/createRobotTask

        #### Parâmetros:
        - robot_id (str): Id do robô onde a tarefa será criada
        - environment (str): define o ambiente em que a tarefa será criada
        - task_name (str): nome da tarefa que será criada
        - app_version (int): versão do robô que a tarefa vai utilizar (no caso de tarefas em produção)
        - emails_enabled (bool): Se True, habilita a notificação de e-mails da tarefa
        - log_enabled (bool): Se True, habilita a saída de logs na execução da tarefa
        - pw_crypto_key (str): define a chave de descriptografia RSA das senhas nas tarefas
        - share_encrypted(bool): define se a tarefa pode ou não ser acessada quando uma senha foi criptografada
        - analytic_names(list): define a lista de análises do robô que será executada pela tarefa

        #### Retorna:
        Um dict com informações sobre a tarefa criada.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi('seu_token', 'sua_organização')
        instance.createRobotTask('12345', 'production', 'tarefa 1')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        dSchema = {
            'data':{
                'type': 'robot_tasks',
                'attributes': {
                    'app_version': app_version,
                    'email_notifications_enabled': emails_enabled,
                    'environment': environment,
                    'log_enabled': log_enabled,
                    'name': task_name,
                    'public_key_name': pw_crypto_key,
                    'share_encrypted': share_encrypted,
                    'analytic_names': [analytic_names]
                }
            }
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}/robot_tasks'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.post(url, headers=apiHeaders, json=dSchema)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def putRobotTask(self, task_id, environment: Literal['production', 'development'], 
                        task_name, app_version: int = None, emails_enabled: bool = False, 
                        log_enabled: bool = False, pw_crypto_key: str = None, 
                        share_encrypted: bool = False, analytic_names: list = None) -> dict:
        """
        Atualiza uma tarefa em um robô do Highbond, e em um ambiente específico

        #### Referência:
        https://docs-apis.highbond.com/#operation/putRobotTask

        #### Parâmetros:
        - task_id (str): Id da tarefa que será atualizada
        - environment (str): define o ambiente em que a tarefa será atualizada
        - task_name (str): nome da tarefa que será atualizada
        - app_version (int): versão do robô que a tarefa vai utilizar (no caso de tarefas em produção)
        - emails_enabled (bool): Se True, habilita a notificação de e-mails da tarefa
        - log_enabled (bool): Se True, habilita a saída de logs na execução da tarefa
        - pw_crypto_key (str): define a chave de descriptografia RSA das senhas nas tarefas
        - share_encrypted(bool): define se a tarefa pode ou não ser acessada quando uma senha foi criptografada
        - analytic_names(list): define a lista de análises do robô que será executada pela tarefa

        #### Retorna:
        Um dict com informações sobre a tarefa atualizada.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi('seu_token', 'sua_organização')
        instance.putRobotTask('12345', 'production', 'tarefa 1')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        dSchema = {
            'data':{
                'type': 'robot_tasks',
                'attributes': {
                    'app_version': app_version,
                    'email_notifications_enabled': emails_enabled,
                    'environment': environment,
                    'log_enabled': log_enabled,
                    'name': task_name,
                    'public_key_name': pw_crypto_key,
                    'share_encrypted': share_encrypted,
                    'analytic_names': analytic_names
                }
            }
        }
        
        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_tasks/{task_id}'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.put(url, headers=apiHeaders, json=dSchema)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def deleteRobotTask(self, task_id: str) -> dict:
        """
        Deleta uma tarefa de um robô do Highbond

        #### Referência:
        https://docs-apis.highbond.com/#operation/deleteRobotTask

        #### Parâmetros:
        - task_id (str): Id da tarefa que será deletada

        #### Retorna:
        Um dict com informações sobre a tarefa deletada.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi('seu_token', 'sua_organização')
        instance.deleteRobotTask('12345')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        
        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_tasks/{task_id}'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.delete(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def runRobotTask(self, task_id: str, include: list = ['job_values','result_tables']) -> dict:
        """
        Inicia a execução de uma tarefa de um robô no Highbond

        #### Referência:
        https://docs-apis.highbond.com/#operation/runRobotTask

        #### Parâmetros:
        - task_id (str): Id da tarefa que será executada
        - include (list): Define se os valores job_values e result_tables vão sair na resposta

        #### Retorna:
        Um dict com informações sobre a a execução da tarefa.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi('seu_token', 'sua_organização')
        instance.runRobotTask('12345', ['job_values','result_tables'])
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        includeCheckList = ['job_values','result_tables']

        if not isinstance(include, list):
            raise Exception('Precisa ser configurado no formato "list"')
        else:
            for item in include:
                if not item in includeCheckList:
                    raise Exception(f'"{item}" não é um valor permitido para essa API')

            strInclude = ''
            for item in include:
                strInclude = strInclude + ',' + item
            strInclude = strInclude[1:]

        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        
        qParameters = {
            'include': strInclude
        }
        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_tasks/{task_id}/run_now'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.post(url, headers=apiHeaders, params=qParameters)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def getValues(self, task_id: str, ) -> dict:
        """
        Lista os valores em uma tarefa de um robô.

        #### Referência: 
        https://docs-apis.highbond.com/#operation/getValues

        #### Parâmetros:
        - task_id (str): Id da tarefa, onde os parâmetros estão disponíveis

        #### Retorna:
        Um dicionário contendo informações sobre os parâmetros da tarefa.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='sua_organizacao')
        result = instance.getValues(task_id='123')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo informações sobre os jobs do robô.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server

        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_tasks/{task_id}/values'

        # AÇÃO E RESPOSTA
        try:
           
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())
            
        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def putValues(self, task_id: str, multi_mode: bool, analytic_name: str = None, parameter_id: str = None, 
                  encrypted: bool = None, value: str = None, 
                  value_type: Literal["character","date","datetime","file","logical","number","table","time"] = None, 
                  values_list: List[list] = None) -> dict:
        """
        Atualiza o valor de um parâmetro de uma tarefa

        #### Referência:
        https://docs-apis.highbond.com/#operation/putValues

        #### Parâmetros:
        - task_id (str): Id da tarefa que será atualizada
        - multi_mode (bool): Define se o método atualizará um valor ou vários valores
        - analytic_name (str): define o nome da análise que será alterada se multi_mod = False
        - parameter_id (str): define qual parâmetro será alterado se multi_mod = False
        - encrypted (bool): Se True, define que o parâmetro é protegido e mascarado como uma senha se multi_mod = False
        - value (str): conteúdo do valor que será alterado se multi_mod = False
        - value_type (str): tipo do valor que será alterado se multi_mod = False
        - values_list (list): se multi_mod = True, recebe [analytic_name, parameter_id, encrypted, value, value_type] para cada valor que será alterado

        #### Retorna:
        Um dict com informações sobre os parâmetros que serão atualizados.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso se multi_mod = False:
        ```python
        instance = hbapi('seu_token', 'sua_organização')
        instance.putValues('1234565', multi_mod=False, 'Nome da Análise', 'Nome do ParÂmetro', False, 'Novo Valor', 'character')
        ```

        #### Exemplo de uso se multi_mod = True
        ```python
            instance = hbapi('token', 'organizacao')
            instance.putValues('tarefa', multi_mod=True, values_list=[
                ['Nome da Análise 1', 'Nome do Parâmetro 1', True, 'Novo Valor 1', 'character'], 
                ['Nome da Análise 2', 'Nome do Parâmetro 2', True, 'Novo Valor 2', 'character']
            ]
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - Caso haja calores com senha entre os parâmetros da tarefa, putValues deve sempre rodar em multi_mod=True
        pois, o parâmetro de senha deve ser passado junto dos outros.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        
        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_tasks/{task_id}/values'

        # AÇÃO E RESPOSTA
        try:

            if multi_mode == False:
                if values_list != None:
                    dSchema = {
                        "data": [
                            {
                                "type": "values",
                                "attributes": {
                                    "analytic_name": analytic_name,
                                    "parameter_id": parameter_id,
                                    "encrypted": encrypted,
                                    "data": {
                                        "value": value,
                                        "type": value_type
                                    }
                                }
                            }
                        ]
                    }
                else:
                    raise Exception('"values_list" não pode ser definido se multi_mod=False')
            else:
                if not values_list == None:
                    for item in values_list:
                        if len(item) != 5:
                            raise Exception('Um dos valores de values_list foi mal configurado')
                        dSchema = {
                            "data": []
                        }

                        hashTemp = {
                                "type": "values",
                                "attributes": {
                                    "analytic_name": item[0],
                                    "parameter_id": item[1],
                                    "encrypted": item[2],
                                    "data": {
                                        "value": item[3],
                                        "type": item[4]
                                    }
                                }
                            }

                    dSchema['data'].append(hashTemp)
                else:
                    raise Exception('"values_list" precisa ser corretamente definido se multi_mod=True')
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.put(url, headers=apiHeaders, json=dSchema)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def getSchedule(self, task_id: str) -> dict:
        """
        Informa sobre o agendamento de uma tarefa.

        #### Referência: 
        https://docs-apis.highbond.com/#operation/getSchedule

        #### Parâmetros:
        - task_id (str): o id da tarefa

        #### Retorna:
        Um dicionário contendo informações sobre os agendamentos da tarefa

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='sua_organizacao')
        result = instance.getRobotJobs(task_id='123')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server

        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_tasks/{task_id}/schedule'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())
            
        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def createSchedule(self, task_id: str, frequency: Literal["once", "hourly", "daily", "weekly", "monthly"], 
                       interval: int = 1, starts_at: str = None, timezone: str = None, days: List[Union[int,str]]= None) -> dict:
        """
        Cria o agendamento de uma tarefa.

        #### Referência: 
        https://docs-apis.highbond.com/#operation/createSchedule

        #### Parâmetros:
        - task_id (str): o id da tarefa
        - frequency (str): frequência de execução do agendamento, pode ser:
            - once: Define que o agendamento só será executado uma vez
            - hourly: Define uma frequência horária (depende do intervalo)
            - daily: Define uma frequência diária (depende do intervalo)
            - weekly: Define uma frequência semanal (depende do intervalo)
            - monthly: Define uma frequência mensal (depende do intervalo)
        - interval (int): o intervalo de tempo, a unidade muda com a frequência escolhida:
            - once: Não é definido
            - hourly: define o intervalo em minutos
            - daily: define o intervalo em dias
            - weekly: define o intervalo em semanas
            - monthly: define o intervalo em meses
        - starts_at (str): datahora da primeira execução do agendamento (yyyy-mm-dd THH:MM:SS.sssZ)
        - timezone (str): fusohorário da hora definida, (America/Sao_Paulo, conforme Ref.: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)
        - days (list of integers or strings): define diferentes intervalos de execução para cada frequência, exceto por "once", "hourly" e "daily"
            - weekly: em quais dias da semana o agendamento será executado, sendo 0 domingo e 6 sábado, a lista pode ter 1 ou mais dias
            - monthly: em quais dias do mês o agendamento será executado, os dias podem ser definidos entre 1 e 28. Ou "last_day" para o último dia do mês, a lista só pode ter um valor

        #### Retorna:
        Um dicionário contendo informações sobre os agendamentos da tarefa

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='sua_organizacao')
        instance.createSchedule('67336','daily', 2, starts_at='2024-02-17T22:00:00Z',timezone='America/Sao_Paulo')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        
        frequencyNullCheckList = ['once', 'hourly', 'daily']

        if frequency in frequencyNullCheckList:
            hashDays = {}
        else:
            hashDays = {'days': days}

        dSchema = {
            "data": {
                "type": "schedule",
                "attributes": {
                    "frequency": frequency,
                    "interval": interval,
                    "starts_at": starts_at,
                    "starts_at_timezone": timezone,
                    "settings": hashDays
                }
            }
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_tasks/{task_id}/schedule'

        # AÇÃO E RESPOSTA
        try:
            if frequency == "once":
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fuso-horário!')
                if interval != 1:
                    raise Exception('O intervalo não pode ser diferente de 1 para essa frequência')
                
            elif frequency == 'hourly':
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fuso-horário!')
                if interval <= 0:
                    raise Exception('É preciso definir um intervalo em horas para essa frequência!')
                
            elif frequency == 'daily':
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fusohorário!')
                if interval <= 0:
                    raise Exception('É preciso definir um intervalo em dias para essa frequência!')
            
            elif frequency == 'weekly':
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fuso-horário!')
                if interval <= 0:
                    raise Exception('É preciso definir um intervalo em dias para essa frequência!')

                for day in days:
                    if not 0 <= day <= 6:
                        raise Exception('O parâmetro "days" não foi definido corretamente')
            
            elif frequency == 'monthly':
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fuso-horário!')
                if interval <= 0:
                    raise Exception('É preciso definir um intervalo em dias para essa frequência!')

                if len(days) == 1:
                    for day in days:
                        if isinstance(day, str):
                            if not day == "last_day":
                                raise Exception('O parâmetro "days" não foi definido corretamente')
                        else:
                            if not 1 <= day <= 28:
                                raise Exception('O parâmetro "days" não foi definido corretamente')
                else:
                    raise Exception('Para esta frequência, o parâmetro "days" não pode ter mais de 1 item')
                
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.post(url, headers=apiHeaders, json=dSchema)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def putSchedule(self, task_id: str, frequency: Literal["once", "hourly", "daily", "weekly", "monthly"], 
                       interval: int = 1, starts_at: str = None, timezone: str = None, days: List[Union[int,str]]= None) -> dict:
        """
        Atualiza o agendamento de uma tarefa.

        #### Referência: 
        https://docs-apis.highbond.com/#operation/putSchedule

        #### Parâmetros:
        - task_id (str): o id da tarefa
        - frequency (str): frequência de execução do agendamento, pode ser:
            - once: Define que o agendamento só será executado uma vez
            - hourly: Define uma frequência horária (depende do intervalo)
            - daily: Define uma frequência diária (depende do intervalo)
            - weekly: Define uma frequência semanal (depende do intervalo)
            - monthly: Define uma frequência mensal (depende do intervalo)
        - interval (int): o intervalo de tempo, a unidade muda com a frequência escolhida:
            - once: Não é definido
            - hourly: define o intervalo em minutos
            - daily: define o intervalo em dias
            - weekly: define o intervalo em semanas
            - monthly: define o intervalo em meses
        - starts_at (str): datahora da primeira execução do agendamento (yyyy-mm-dd THH:MM:SS.sssZ)
        - timezone (str): fusohorário da hora definida, (America/Sao_Paulo, conforme Ref.: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)
        - days (list of integers or strings): define diferentes intervalos de execução para cada frequência, exceto por "once", "hourly" e "daily"
            - weekly: em quais dias da semana o agendamento será executado, sendo 0 domingo e 6 sábado, a lista pode ter 1 ou mais dias
            - monthly: em quais dias do mês o agendamento será executado, os dias podem ser definidos entre 1 e 28. Ou "last_day" para o último dia do mês, a lista só pode ter um valor

        #### Retorna:
        Um dicionário contendo informações sobre os agendamentos da tarefa

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='sua_organizacao')
        instance.putSchedule('67336','daily', 2, starts_at='2024-02-17T22:00:00Z',timezone='America/Sao_Paulo')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        
        frequencyNullCheckList = ['once', 'hourly', 'daily']

        if frequency in frequencyNullCheckList:
            hashDays = {}
        else:
            hashDays = {'days': days}

        dSchema = {
            "data": {
                "type": "schedule",
                "attributes": {
                    "frequency": frequency,
                    "interval": interval,
                    "starts_at": starts_at,
                    "starts_at_timezone": timezone,
                    "settings": hashDays
                }
            }
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_tasks/{task_id}/schedule'

        # AÇÃO E RESPOSTA
        try:
            if frequency == "once":
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fuso-horário!')
                if interval != 1:
                    raise Exception('O intervalo não pode ser diferente de 1 para essa frequência')
                
            elif frequency == 'hourly':
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fuso-horário!')
                if interval <= 0:
                    raise Exception('É preciso definir um intervalo em horas para essa frequência!')
                
            elif frequency == 'daily':
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fusohorário!')
                if interval <= 0:
                    raise Exception('É preciso definir um intervalo em dias para essa frequência!')
            
            elif frequency == 'weekly':
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fuso-horário!')
                if interval <= 0:
                    raise Exception('É preciso definir um intervalo em dias para essa frequência!')

                for day in days:
                    if not 0 <= day <= 6:
                        raise Exception('O parâmetro "days" não foi definido corretamente')
            
            elif frequency == 'monthly':
                if starts_at == None:
                    raise Exception('É preciso definir corretamente a data da execução para eseta frequência!')
                if timezone == None:
                    raise Exception('É preciso definir corretamente o fuso-horário!')
                if interval <= 0:
                    raise Exception('É preciso definir um intervalo em dias para essa frequência!')

                if len(days) == 1:
                    for day in days:
                        if isinstance(day, str):
                            if not day == "last_day":
                                raise Exception('O parâmetro "days" não foi definido corretamente')
                        else:
                            if not 1 <= day <= 28:
                                raise Exception('O parâmetro "days" não foi definido corretamente')
                else:
                    raise Exception('Para esta frequência, o parâmetro "days" não pode ter mais de 1 item')
                
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.put(url, headers=apiHeaders, json=dSchema)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def deleteSchedule(self, task_id: str):
        """
        Deleta o agendamento de uma tarefa

        #### Referência:
        https://docs-apis.highbond.com/#operation/deleteRobotTask

        #### Parâmetros:
        - task_id (str): Id da tarefa

        #### Retorna:
        Um dict com informações sobre o agendamento deletado.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi('seu_token', 'sua_organização')
        instance.deleteRobotTask('12345')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        
        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_tasks/{task_id}/schedule'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.delete(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

# Robot Jobs
    def getRobotJobs(self, robot_id: str, environment: str, 
                include: list = ['robot','task','triggered_by'], 
                page_size: int = 100, page_number: int = 1) -> dict:
        """
        Lista os jobs (execuções) de um robô ACL.

        #### Referência: 
        https://docs-apis.highbond.com/#operation/getRobotJobs
 
        #### Parâmetros:
        - robot_id (str): O ID do robô ACL onde os jobs estão armazenados.
        - environment (str): O ambiente onde os jobs estão armazenados. Pode ser 'production' para o ambiente de produção ou 'development' para o ambiente de desenvolvimento.
        - include (list): Controla se os dados 'robot', 'task' e 'triggered_by' aparecem no JSON de saída. Todos os campos marcados na consulta pela classe são incluídos. Padrão é ['robot','task','triggered_by'].
        - page_size (int): Controla a quantidade de registros que aparecerão em cada consulta. Padrão é 100.
        - page_number (int): Controla o número da página. A API divide em páginas quando o número de registros ultrapassa page_size. Padrão é 1.

        #### Retorna:
        Um dicionário contendo informações sobre os jobs do robô.

        #### Exceções:
        - Sobe exceção se o ambiente não estiver definido corretamente.
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='sua_organizacao')
        result = instance.getRobotJobs(robot_id='123', environment='production')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo informações sobre os jobs do robô.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server

        includeCheckList = ['robot', 'task', 'triggered_by']

        if not isinstance(include, list):
            raise Exception('Precisa ser configurado no formato "list"')
        else:
            for item in include:
                if not item in includeCheckList:
                    raise Exception(f'"{item}" não é um valor permitido para essa API')

            strInclude = ''
            for item in include:
                strInclude = strInclude + ',' + item
            strInclude = strInclude[1:]

        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'env': environment,
            'include': strInclude,
            'page[size]': str(page_size),
            'page[number]': str(page_number)
        }
        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}/jobs'

        # AÇÃO E RESPOSTA
        try:
            if not ((environment == 'production') or (environment == 'development')):
                raise Exception('O ambiente não foi definido corretamente.')
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, params=qParameters, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())
            
        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def deleteRobotJobs(self, job_id: str):
        """
        Deleta um registro de execução do robô

        #### Referência:
        https://docs-apis.highbond.com/#operation/deleteRobotJobs

        #### Parâmetros:
        - job_id (str): Id do registro de execução

        #### Retorna:
        Um dict com informações sobre o registro de execução deletado

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi('seu_token', 'sua_organização')
        instance.deleteRobotJobs('12345')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        
        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/jobs/{job_id}'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.delete(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

# Analytic Scripts
    def getRobotApp(self, robot_id: str, robot_app_id: str):
        """
        Informa sobre uma versão específica de desenvolvimentode um robô do ACL.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getRobotApp

        #### Parâmetros:
        - robot_id (str): O ID do robô ACL para o qual os arquivos estão armazenados.
        - robot_app_id (str): O id da versão especificada

        #### Retorna:
        - Um dict com os dados solicitados

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getRobotApp(robot_id='123', robot_app_id='456')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}/robot_apps/{robot_app_id}'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    # TODO (Solved): getRobotApps()
    def getRobotApps(self, robot_id):
        """
        Informa sobre todas as versões de desenvolvimento de um robô do ACL.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getRobotApps

        #### Parâmetros:
        - robot_id (str): O ID do robô ACL para o qual os arquivos estão armazenados.

        #### Retorna:
        - Um dict com os dados solicitados

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getRobotApp(robot_id='123', robot_app_id='456')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}/robot_apps'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def createRobotApp(self, robot_id: str, code_page: int, comment: str, is_unicode: bool, input_file: str) -> dict:
        """
        Método que faz upload dos arquivos relacionados de um robô ACL

        #### Referência:
        - https://docs-apis.highbond.com/#operation/createRobotApp
        
        #### Parâmetros:
        - robot_id (str): id do robô
        - code_page (int): id do encoding do robô (21 - Brazil) (Ref.: https://en.wikipedia.org/wiki/Code_page)
        - comment (str): comentário da nova versão
        - is_unicode (bool): define se o projeto está na versão unicode ou não
        - input_file(str): uma string com o caminho para o arquivo .acl do projeto

        #### Retorna:
        Um dicionário contendo informações sobre o arquivo recém-criado.

        #### Exceções:
        - Raises Exception se a requisição API falhar com códigos de status diferentes de 200.
        - Raises Exception se houver uma falha desconhecida.
        - Raises Exception se a entidade for considerada improcessável (código 422).

        #### Exemplo de uso:
        ```python
        instance = hbapi('seu_token', 'sua_organização')
        result = instance.createRobotApp(
            robot_id='123', code_page=21, comment='Versão de teste ro robô', 
            is_unicode=False, input_file='caminho/do/arquivo.acl'
            )
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.

        """
        
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        dSchema = {
            'code_page': code_page,
            'comment': comment,
            'is_unicode': is_unicode,
            'file': open(input_file, 'rb')
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}/robot_apps'

        try:

            if self.talkative == True:
                print('Iniciando a requisição HTTP')

            Response = rq.post(url, headers=apiHeaders, files=dSchema)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível\n{e}')

# Robot Script versions (Robô Python)
    def getRobotScriptVersion(self, robot_id: str, version_id: str, include: Literal[None, 'analytics'] = 'analytics'):
        """
        Informa sobre uma versão específica de desenvolvimentode um robô do ACL.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getRobotScriptVersion

        #### Parâmetros:
        - robot_id (str): O ID do robô ACL.
        - version_id (str): O id da versão especificada

        #### Retorna:
        - Um dict com os dados solicitados

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getRobotScriptVersion(robot_id='123', version_id='456')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        qParameters = {
            'include': include
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}/versions/{version_id}'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

# ACL Robot Related Files
    def getRobotFiles(self, robot_id: str, environment: str) -> dict:
        """
        Lista os arquivos relacionados a um robô ACL em um ambiente específico.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getRobotFile

        #### Parâmetros:
        - robot_id (str): O ID do robô ACL para o qual os arquivos estão armazenados.
        - environment (str): O ambiente onde os arquivos estão armazenados. Pode ser 'production' para o ambiente de produção ou 'development' para o ambiente de desenvolvimento.

        #### Retorna:
        Um dicionário contendo informações sobre os arquivos do robô.

        #### Exceções:
        - Sobe exceção se o ambiente não estiver definido corretamente.
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getRobotFiles(robot_id='123', environment='production')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os arquivos do robô.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'env': environment
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}/robot_files'

        # AÇÃO E RESPOSTA
        try:
            if not ((environment == 'production') or (environment == 'development')):
                raise Exception('O ambiente não foi definido corretamente.')
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, params=qParameters, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def createRobotFile(self, inputFile: str, robot_id: str, environment: Literal['production', 'development']) -> dict:
        """
        Método que faz upload dos arquivos relacionados de um robô ACL

        #### Referência:
        - https://docs-apis.highbond.com/#operation/createRobotFile
        
        #### Parâmetros:
        - inputFile (str): O caminho do arquivo a ser enviado para a API como parte da criação.
        - robot_id (str): O ID do robô ACL para o qual o arquivo será associado.
        - environment (str): O ambiente onde o arquivo será criado. Pode ser 'production' para o ambiente de produção ou 'development' para o ambiente de desenvolvimento.

        #### Retorna:
        Um dicionário contendo informações sobre o arquivo recém-criado.

        #### Exceções:
        - Raises Exception se o ambiente não estiver definido corretamente.
        - Raises Exception se a requisição API falhar com códigos de status diferentes de 200.
        - Raises Exception se houver uma falha desconhecida.
        - Raises Exception se a entidade for considerada improcessável (código 422).

        #### Exemplo de uso:
        ```python
        instance = SuaClasse()
        result = instance.createRobotFile(inputFile='caminho/do/arquivo.txt', robot_id='123', environment='production')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - O caminho do arquivo a ser enviado é especificado em 'inputFile'.
        - A resposta é um dicionário contendo informações sobre o arquivo recém-criado.

        """
        
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Accept': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'env': environment
        }

        dSchema = {
            'file': open(inputFile, 'rb')
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robots/{robot_id}/robot_files'

        
        try:
            if not ((environment == 'production') or (environment == 'development')):
                raise Exception('O ambiente não foi definido corretamente.')

            if self.talkative == True:
                print('Iniciando a requisição HTTP')

            Response = rq.post(url, params=qParameters, headers=apiHeaders, files=dSchema)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 422:
                raise Exception('Código: 422\nMensagem: Entidade improcessável')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível\n{e}')

# TODO: getRobotFile() função para receber dados de metadata dos arquivos

    def deleteRobotFile(self, file_id: str) -> dict:
        """
        Deleta um arquivo de um robô ACL

        #### Referência:
        - https://docs-apis.highbond.com/#operation/createRobotFile
        
        #### Parâmetros:
        - file_id (str): O ID do arquivo dentro do robô ACL a ser deletado.

        #### Retorna:
        Um dicionário contendo informações sobre o status da deleção.

        #### Exceções:
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='sua_organizacao')
        result = instance.deleteRobotFile(file_id='123')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo informações sobre o status da deleção.
        """
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server

        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_files/{file_id}'

        try:
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
                
            Response = rq.delete(url, headers=apiHeaders)
            
            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('\nCódigo: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('\nCódigo: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('\nCódigo: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('\nCódigo: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                if self.talkative == True:
                    print('\nCódigo: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def downloadFile(self, file_id: str, out_file: str) -> bytes:
        """
        Faz o download de um arquivo relacionado a um robô ACL.

        Referência:
        - https://docs-apis.highbond.com/#operation/downloadFile

        Parâmetros:
        - file_id (str): O ID do arquivo a ser baixado.
        - out_file (str): O caminho do arquivo de saída onde o conteúdo baixado será salvo.

        Retorna:
        Bytes contendo o conteúdo do arquivo baixado.

        Exceções:
        - Raises Exception se a requisição API falhar com códigos de status diferentes de 200.
        - Raises Exception se houver uma falha desconhecida.
        - Raises Exception se o arquivo não for encontrado após o download.

        Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='sua_organizacao')
        file_content = instance.downloadFile(file_id='123', out_file='caminho/do/arquivo/baixado.txt')
        ```

        Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de log.
        - O conteúdo do arquivo baixado é salvo no caminho especificado em 'out_file'.
        """
        protocol = 'https'
        token = self.token
        org_id = self.organization_id
        server = self.server

        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/robot_files/{file_id}/download'

        try:
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')

            Response = rq.get(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('\nCódigo: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('\nCódigo: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('\nCódigo: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 415:
                raise Exception('\nCódigo: 415\nMensagem: Tipo de dado não suportado pelo API, altere o Content-Type no cabeçalho da requisição')
            elif Response.status_code == 200:
                if self.talkative == True:
                    print('\nCódigo: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    
                    output = pl.Path(out_file)
                    output.write_bytes(Response.content)
                    if not os.path.exists(out_file):
                        raise Exception('\nArquivo não encontrado após o download')
                else:
                    output = pl.Path(out_file)
                    output.write_bytes(Response.content)
                    if not os.path.exists(out_file):
                        raise Exception('\nArquivo não encontrado após o download')
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def getEntities(self, fields_entities: str = 'title,description,created_at,updated_at,parent,children_count,entity_category', page_size: int = 25, page_number: int = 1) -> dict:
        """
        Lista os arquivos relacionados a um robô ACL em um ambiente específico.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getStrategyRiskSegment

        #### Parâmetros:
        - fields_entities: parâmetro que define quais campos serão retornados na API (padrão é tudo)
        - page_size: parâmetro que define a quantidade de registros que retornará a cada consulta
        - page_number: parâmetro que seleciona a página de resposta (se a quantidade total de registros ultrapassar page_size)

        #### Retorna:
        Um dicionário contendo informações sobre as entidades da organização

        #### Exceções:
        - Sobe exceção se o ambiente não estiver definido corretamente.
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getEntities()
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os arquivos do robô.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token  = self.token
        org_id = self.organization_id
        server = self.server

        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'fields[entities]': fields_entities,
            'page_size': page_size,
            'page[number]': base64.encodebytes(str(page_number).encode()).decode()
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/entities'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative:
                print('Iniciando a requisição HTTP...')
            response = rq.get(url,params=qParameters ,headers=apiHeaders)

            if response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif response.status_code == 415:
                raise Exception('Código: 415\nMensagem: Tipo de mídia não suportado')
            elif response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return response.json()
                else:
                    return response.json()
            else:
                raise Exception(response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def getStrategyRisks(self, 
                         fields: str = 'title,description,status,score,residual_score,heat,residual_heat,strategy_custom_attributes,risk_manager_risk_id,created_at,updated_at', 
                         size: int = 10, 
                         page: int = 1) -> dict:
        """
        Lista os arquivos relacionados a um robô ACL em um ambiente específico.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getStrategyRisks

        #### Parâmetros:
        - fields: Parâmetro com os campos escondidos dos riscos estratégicos
        - size: A quantidade de itens que vão aparecer na consulta de riscos
        - page: Caso existam mais riscos do que o valor do parâmetro do "size", o número da página aumenta em 1

        #### Retorna:
        Um dicionário contendo informações sobre os riscos consultados

        #### Exceções:
        - Sobe exceção se o ambiente não estiver definido corretamente.
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getStrategyRisks(
            fields='title,description,status,score,residual_score,heat,residual_heat,strategy_custom_attributes,risk_manager_risk_id,created_at,updated_at', 
            size=10, 
            page=1
            )
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os arquivos do robô.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token  = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'fields[strategy_risks]': fields,
            'page[size]' : size,
            'page[number]': base64.encodebytes(str(page).encode()).decode()
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/strategy_risks'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, params=qParameters, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def getStrategySegments(self, 
                            size: int = 10, 
                            page: int = 1) -> dict:
        """
        Lista os arquivos relacionados a um robô ACL em um ambiente específico.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getStrategySegments

        #### Parâmetros:
        - size: A quantidade de itens que vão aparecer na consulta de segmentos
        - page: Caso existam mais riscos do que o valor do parâmetro do "size", o número da página aumenta em 1

        #### Retorna:
        Um dicionário contendo informações sobre os segmentos consultados

        #### Exceções:
        - Sobe exceção se o ambiente não estiver definido corretamente.
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getStrategySegments(
            size=10, 
            page=1
            )
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os arquivos do robô.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token  = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'page[size]' : size,
            'page[number]': base64.encodebytes(str(page).encode()).decode()
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/strategy_segments'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, params=qParameters, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def getStrategyRiskSegments(self, strategy_risk_id: str, size: int, page: int ) -> dict:
        """
        Lista os arquivos relacionados a um robô ACL em um ambiente específico.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getStrategyRiskSegments

        #### Parâmetros:
        - strategy_risk_id: id do risco estratégico a ser consultado
        - size: quantidade de registros nesta consulta
        - page: página consultada

        #### Retorna:
        Um dicionário contendo informações sobre o risco estratégico consultado

        #### Exceções:
        - Sobe exceção se o ambiente não estiver definido corretamente.
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getStrategyRiskSegments(strategy_risk_id='45323', size=10, page=1)
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os arquivos do robô.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token  = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        
        qParameters = {
            'page[size]': size,
            'page[number]': base64.encodebytes(str(page).encode()).decode()
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/strategy_risks/{strategy_risk_id}/strategy_segments'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative == True:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative == True:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')

    def getStrategyRiskSegment(self, 
                               strategy_risk_id: str, 
                               segment_id: str,
                               segment_fields: str = 'name,score,strategy_factors,created_at,updated_at', 
                               factors_fields: str = 'id,treatment_value,treatment_weight,treatment_factors,severity_value'
                               ) -> dict:
        """
        Lista os arquivos relacionados a um robô ACL em um ambiente específico.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getStrategyRiskSegment

        #### Parâmetros:
        - strategy_risk_id: id do risco estratégico a ser consultado
        - segment_id: id do segmento consultado
        - segment_fields: campos ocultos de segmentos
        - factors_fields: campos ocultos de fatores

        #### Retorna:
        Um dicionário contendo informações sobre o segmento do risco estratégico consultado consultado

        #### Exceções:
        - Sobe exceção se o ambiente não estiver definido corretamente.
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getStrategyRiskSegment(strategy_risk_id='45323', segment_id='48751', segment_fields='name,score,strategy_factors')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os arquivos do robô.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token  = self.token
        org_id = self.organization_id
        server = self.server
        
        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }
        
        if factors_fields == '':
            factors_fields = None
        
        if segment_fields == '':
            raise Exception('O método não pode ser chamado sem um campo de consulta')

        qParameters = {
            'fields[strategy_segments]': segment_fields,
            'fields[strategy_factors]': factors_fields
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/strategy_risks/{strategy_risk_id}/strategy_segments/{segment_id}'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative:
                print('Iniciando a requisição HTTP...')
            Response = rq.get(url, params=qParameters, headers=apiHeaders)

            if Response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif Response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif Response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif Response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif Response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return Response.json()
                else:
                    return Response.json()
            else:
                raise Exception(Response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')
    
    def getStrategyObjectives(self, page_size: int = 10, page_number: int = 1) -> dict:
        """
        Lista os arquivos relacionados a um robô ACL em um ambiente específico.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getStrategyRiskSegment

        #### Parâmetros:
        - page_size: parâmetro que define a quantidade de registros retornados

        #### Retorna:
        Um dicionário contendo informações sobre o segmento do risco estratégico consultado consultado

        #### Exceções:
        - Sobe exceção se o ambiente não estiver definido corretamente.
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getStrategyRiskSegment(strategy_risk_id='45323', segment_id='48751', segment_fields='name,score,strategy_factors')
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os arquivos do robô.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token  = self.token
        org_id = self.organization_id
        server = self.server

        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'page[size]': page_size,
            'page[number]': base64.encodebytes(str(page_number).encode()).decode()
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/strategy_objectives'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative:
                print('Iniciando a requisição HTTP...')
            response = rq.get(url,params=qParameters ,headers=apiHeaders)

            if response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return response.json()
                else:
                    return response.json()
            else:
                raise Exception(response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')
    
    def getObjectives(self, 
                      project_id: str, 
                      fields = 'title,description,reference,division_department,owner,executive_owner,created_at,updated_at,project,assigned_user,custom_attributes,position,risk_control_matrix_id,walkthrough_summary_id,testing_round_1_id,testing_round_2_id,testing_round_3_id,testing_round_4_id,entities,framework,framework_origin,risk_assurance_data,planned_start_date,actual_start_date,planned_end_date,actual_end_date,planned_milestone_date,actual_milestone_date',
                      page_size = 25,
                      page_number = 1) -> dict:
        """
        Lista os objetivos de um projeto ACL.

        #### Referência:
        https://docs-apis.highbond.com/#operation/getObjectives

        #### Parâmetros:
        - page_size: parâmetro que define a quantidade de registros retornados

        #### Retorna:
        Um dicionário contendo informações sobre o segmento do risco estratégico consultado consultado

        #### Exceções:
        - Sobe exceção se o ambiente não estiver definido corretamente.
        - Sobe exceção se a requisição API falhar com códigos de status diferentes de 200.
        - Sobe exceção se houver uma falha desconhecida.

        #### Exemplo de uso:
        ```python
        instance = hbapi(token='seu_token', organization_id='id_da_organização')
        result = instance.getObjectives(fields='title, description', page_size=25, page_number=1)
        ```

        #### Observações:
        - Certifique-se de que a propriedade 'talkative' esteja configurada corretamente para controlar as mensagens de sucesso.
        - A resposta é um dicionário contendo as informações sobre os arquivos do robô.

        """
        # CONFIGURAÇÃO DO MÉTODO
        protocol = 'https'
        token  = self.token
        org_id = self.organization_id
        server = self.server
        parent_resource_type = 'projects'
        parent_resource_id = project_id

        apiHeaders = {
            'Content-type': 'application/vnd.api+json',
            'Authorization': f'Bearer {token}'
        }

        qParameters = {
            'fields[objectives]': fields,
            'page[size]': page_size,
            'page[number]': base64.encodebytes(str(page_number).encode()).decode()
        }

        url = f'{protocol}://{server}/v1/orgs/{org_id}/{parent_resource_type}/{parent_resource_id}/objectives'

        # AÇÃO E RESPOSTA
        try:
            
            if self.talkative:
                print('Iniciando a requisição HTTP...')
            response = rq.get(url,params=qParameters ,headers=apiHeaders)

            if response.status_code == 400:
                raise Exception('Código: 400\nMensagem: Falha na requisição API')
            elif response.status_code == 401:
                raise Exception('Código: 401\nMensagem: Falha na autenticação com token')
            elif response.status_code == 403:
                raise Exception('Código: 403\nMensagem: Conexão não permitida pelo servidor')
            elif response.status_code == 404:
                raise Exception('Código: 404\nMensagem: Recurso não encontrado no API')
            elif response.status_code == 200:
                # A PROPRIEDADE Talkative CONTROLA SE AS MENSAGENS 
                # DE SUCESSO VÃO FICAR SAINDO TODA VEZ QUE O MÉTODO RODA
                if self.talkative:
                    print('Código: 200\nMensagem: Requisição executada com sucesso\n')
                    # SAÍDA COM SUCESSO
                    return response.json()
                else:
                    return response.json()
            else:
                raise Exception(response.json())

        except Exception as e:
            print(f'A requisição não foi possível:\n{e}')