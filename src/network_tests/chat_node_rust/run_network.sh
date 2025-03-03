# build docker image and run number_of_nodes containers in detached mode,
# and one in interactive mode.

# set number_of_nodes to value from input parameters of as a default value
if [ -n "$1" ] ; then
  number_of_nodes="$1"
else
  number_of_nodes=50 #  default value
fi

if ! docker build -t chat-node-rust . ; then # check if docker build failed
  echo "Docker build failed. Exiting..."
  exit 1
fi

for (( i=0; i < number_of_nodes; ++i ))
do
  docker run -td --rm chat-node-rust
done

docker run -it --rm chat-node-rust
