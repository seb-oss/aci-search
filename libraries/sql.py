import sys
import yaml
import sqlalchemy as db
from sqlalchemy import Table, Column, Integer, String, Float, MetaData
from sqlalchemy.sql import and_, or_, not_, select
from sqlalchemy_utils import create_database, database_exists

from os.path import expanduser, dirname, realpath, isfile

# Config file
lib_path = dirname(__file__)
config_file = lib_path + '/config.yaml'

if not isfile(config_file):
    sys.exit("configuration file not found: '%s'" % config_file)

with open(config_file, 'r') as config:
    cfg = yaml.safe_load(config)
    try:
        db_driver = cfg['db']['driver']
        db_name = cfg['db'].get('db_name')
        db_host = cfg['db'].get('host')
        db_table_name = cfg['db'].get('table_name'      )
        db_user = cfg['db'].get('user')
        db_password = cfg['db'].get('password')
        db_path = lib_path + '/' + db_name

    except KeyError:
        exit('Configuration file does not have db type specified. See config.yaml sample')

class LocalSqlSession():
    # SQL Connector config
    def __init__(self, db_table_name='faults'):
        if db_driver in ['sqlite3', 'sqlite']:
            self.engine = db.create_engine('sqlite+pysqlite:///{}.db'.format(db_path))
        elif db_driver == 'mysql':
            mysql_url = 'mysql+pymysql://{}:{}@{}/{}'.format(db_user, db_password, db_host, db_name)
            if not database_exists(mysql_url):
                create_database(mysql_url)
            self.engine = db.create_engine(mysql_url)

        self.conn = self.engine.connect()
        self.meta = db.MetaData(self.engine)

        if db_table_name == 'faults':
            self.table = Table('faults', self.meta,
                    Column('hash', String(9), primary_key=True, nullable=False),
                    Column('severity', String(15)),
                    Column('domain', String(20)),
                    Column('type', String(20)),
                    Column('cause', String(40)),
                    Column('descr', String(800)),
                    Column('lifeCycle', String(20), quote=False),
                    Column('status', String(30)),
                    Column('created', String(30)),
                    Column('timeStamp', String(16), quote=False),
                    Column('dn', String(400)),
                    Column('fabric', String(15)),
                    Column('code', String(15)))

        elif db_table_name == 'lldpInfo':
            self.table = Table('lldpInfo', self.meta,
                    Column('nodeName', String(10), quote=False, primary_key=True, nullable=False),
                    Column('nodeId', String(4), quote=False),
                    Column('interface', String(50), primary_key=True, nullable=False),
                    Column('neighbor', String(50)),
                    Column('nbInterface', String(50), quote=False),
                    Column('timeStamp', String(17), quote=False))

        self.checkIfExists(db_table_name)

    def checkIfExists(self, table_name):
        if not self.engine.dialect.has_table(self.engine, table_name):
            self.meta.create_all(self.engine, tables=[self.table])
        return

    def getFaults(self, env=None, fault_hash='%', severity='%'):
        s = select([self.table]).where(
                and_(
                    self.table.c.fabric == env,
                    self.table.c.hash.like(fault_hash),
                    self.table.c.severity.like(severity)
                    )
                )
        results = self.conn.execute(s).fetchall()
        dict_results = []
        for row in results:
            row_as_dict = dict(row)
            dict_results.append(row_as_dict)

        return dict_results

    def deleteFault(self, fault_hash):
        self.conn.execute(self.table.delete().where(self.table.c.hash==fault_hash))

    def insert(self, values):
        self.conn.execute(self.table.insert(), values)

    def getLldpByPrefix(self, prefix_list):
        dict_results = []
        for prefix in prefix_list:
            prefix = '%{}%'.format(prefix)
            s = select([self.table]).where(
                    self.table.c.nodeName.like(prefix),
                    )
            results = self.conn.execute(s).fetchall()
            for row in results:
                row_as_dict = dict(row)
                dict_results.append(row_as_dict)

        return dict_results

    def updateLldpInfo(self, values):
        self.conn.execute(self.table.insert(), values)
        '''
        self.conn.execute(self.table.update().where(
                and_(self.table.c.nodeName == values['nodeName'],
                    self.table.c.interface == values['interface'])
                ).values(values))
        '''

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()
