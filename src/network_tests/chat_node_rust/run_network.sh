# build docker image and run number_of_nodes containers in detached mode,
# and one in interactive mode.

# set number_of_nodes to value from input parameters of as a default value
if [ -n "$1" ] ; then
  number_of_nodes="$1"
else
  #  default value
  number_of_nodes=50
fi

docker build -t chat-node-rust .

#number_of_nodes=100
for (( i=0; i < number_of_nodes; ++i ))
do
  docker run -td --rm chat-node-rust
done

docker run -it --rm chat-node-rust
