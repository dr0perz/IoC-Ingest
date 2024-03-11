# IoC-Ingest
Herramienta de ingesta de IoCs de forma centralizada

La presente herramienta integrara en una unica pantalla varios sistemas de seguridad para añadir IoCs, en este caso el EDR de Kaspersky y un firewall de Palo Alto

Se podran añadir los sistemas de seguridad que deseemos integrar, asi de una forma centralizada y rapida añadiremos IoCs en todos los sistemas de seguridad a la vez mediante llamadas API

# Palo Alto
En el caso de Palo Alto partimos del supuesto que ya tenemos una regla de bloqueo creada y dentro de esta regla tenemos como origen un grupo de objetos al que vamos a añadir los IOC

# EDR Kaspersky
Hay que tener en cuenta el siguiente comportamiento de la API de Kaspersky, si dentro de las Prevention Rules del EDR de Kaspersky ya tenemos IoCs añadidos, para añadir nuevos IoC, tenemos que realizar una consulta para obtener las Prevention Rules actualmente activas para despues poder sumar los nuevos IoC que queremos añadir.

Si no realizamos este paso, se borraran las Prevention Rules que tenemos activas y solo quedaran activas las nuevas que vayamos a añadir
