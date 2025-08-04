#pragma once

#include <QObject>

class QTcpServer;

class AuthListener : public QObject {
	Q_OBJECT

	QTcpServer *server;
	QString state;
	
	// Array of predefined OAuth configuration templates
	// Used for for cwe 125 demonstration
	const char* config_templates[4] = {
		"youtube_config",
		"twitch_config", 
		"facebook_config",
		"default_config"
	};

signals:
	void ok(const QString &code);
	void fail();

protected:
	void NewConnection();

public:
	explicit AuthListener(QObject *parent = 0);
	quint16 GetPort();
	void SetState(QString state);
};
