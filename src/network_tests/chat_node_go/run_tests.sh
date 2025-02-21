
docker build -t chat-node-go .

max=30
for (( i=0; i < $max; ++i ))
do
    docker run -td --rm chat-node-go
done
