go build -o build/ ./...

./build/resource_server &
./build/authorization_server &

read -p "Press enter to allow client to access resource..."
./build/client

for n in $(jobs -p)
do
    kill $n
done