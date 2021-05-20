# ./main 1 forwarding-table.txt >tree_basic.txt       # get tree of basic trie
# ./main 9 forwarding-table.txt >tree_compress.txt    # get tree of compress trie

# ./main 10 forwarding-table.txt >port_compress.txt   # get lookup result of basic trie
# ./main 2 forwarding-table.txt >port_basic.txt       # get lookup result of port trie

./main 12 forwarding-table.txt >res_compress.txt    # get time & mem result of basic trie
./main 4 forwarding-table.txt >res_basic.txt        # get time & mem result of port trie
