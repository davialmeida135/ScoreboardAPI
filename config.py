import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))  # Load environment variables from .env file

mysql_user = os.getenv('MYSQL_USER')
mysql_password = os.getenv('MYSQL_PASSWORD')
mysql_host = os.getenv('MYSQL_HOST')
mysql_port = os.getenv('MYSQL_PORT')
mysql_db = os.getenv('MYSQL_DB')

SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_db}'
SQLALCHEMY_TRACK_MODIFICATIONS = False