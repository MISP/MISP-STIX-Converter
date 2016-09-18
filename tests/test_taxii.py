from cabby import create_client

client = create_client(
    'hailataxii.com',
    use_https=False,
    discovery_path='/taxii-discovery-service')

services = client.discover_services()
for service in services:
    print('Service type={s.type}, address={s.address}'.format(s=service))

collections = client.get_collections('http://hailataxii.com/taxii-data')
for collection in collections:
    print (collection.name)
    f = open(collection.name+'.xml','wb')
    content_blocks = client.poll(collection_name=collection.name)
    for block in content_blocks:
        f.write(block.content)
    f.close()
