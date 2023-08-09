#ifndef _IUSER_INTERFACE
#define _IUSER_INTERFACE

class IUserInterface {

public:
	// Initualize User Interface class
	virtual bool Init() = 0;
	// Main thread of user interface
	virtual bool RunInterface() = 0;

private:

};

class ConsoleInterface : public IUserInterface {

public:
	ConsoleInterface() {}
	~ConsoleInterface();

	bool Init();
	bool RunInterface();

private:
	void RunHomeMenu();
	void RunSetupMenu();
	void RunManagementMenu();
};

class GraphicInterface : public IUserInterface {

public:
	GraphicInterface() {}
	~GraphicInterface() {}

	bool Init();
	bool RunInterface();

private:

};

#endif // _IUSER_INTERFACE