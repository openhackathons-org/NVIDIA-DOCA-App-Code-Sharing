CUR_SOURCE=${wildcard *.c}
CUR_OBJS=${patsubst %.c, %.o, $(CUR_SOURCE)}

all: $(CUR_OBJS) 

$(CUR_OBJS):%.o:%.c $(ROOT_DIR)/include/*.h
	$(CC) $(INCLUDE_DIR) $(C_FLAGS) -c $< -o $@
	@cp $@ $(ROOT_DIR)/$(OBJS_DIR)/$@
