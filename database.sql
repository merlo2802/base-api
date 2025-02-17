
CREATE USER base_user WITH LOGIN NOSUPERUSER INHERIT CREATEDB CREATEROLE NOREPLICATION;

--Cambiar contrasenia del usuario
ALTER USER base_user WITH PASSWORD 'DIGITECpassword123SecurityKeySystem1003';

--crear una base de datos con propietario especifico
CREATE DATABASE base_db WITH OWNER base_user;

--Asignar privilegios al usuario de de la base de datos
GRANT ALL PRIVILEGES ON DATABASE base_db TO base_user;