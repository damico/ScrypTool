package org.jdamico.scryptool.launchers;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Checkbox;
import java.awt.CheckboxGroup;
import java.awt.Color;
import java.awt.Container;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.image.BufferedImage;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import org.jdamico.scryptool.commons.Constants;
import org.jdamico.scryptool.crypto.Pkcs11ActionListener;

public class MainGUIDesktop implements ActionListener, PropertyChangeListener { 
	 
		JPanel cards = null; 

		final static String BUTTONPANEL = "Buttons";

		JButton inputButton = null;
		JButton executeButton = null;
		JButton selectProviderButton = null;
		JFileChooser fc = new JFileChooser();
		JFileChooser dc = new JFileChooser();

		String inputButtonLabel = "Input File";
		String outputButtonLabel = "Set output path";
		String selectProviderButtonLabel = "PKCS11 Provider";

		String input = null, output = null;

		
		CheckboxGroup cGroup = null;
		
		private Task task;
		private JProgressBar progressBar;
		boolean done = false;

		JTextArea console;
		
		

		public void addComponentToPane(Container pane) {

			
			
			

			progressBar = new JProgressBar(0, 100);
			progressBar.setString("ready.");
			progressBar.setStringPainted(true);

			selectProviderButton = new JButton(selectProviderButtonLabel);
			selectProviderButton.addActionListener(new Pkcs11ActionListener());
			selectProviderButton.setBounds(305, 5, 194, 30);
			
			inputButton = new JButton(inputButtonLabel);
			inputButton.addActionListener(this);
			inputButton.setBounds(305, 40, 194, 30);
			
			executeButton  = new JButton("Execute!");
			executeButton.setBounds(305, 75, 194, 30);
			executeButton.addActionListener(this);

			console = new JTextArea();
			console.setBackground(Color.BLACK);
			console.setForeground(Color.GREEN);
			

			

					
			console.setBounds(4,154+30+8,494, 160);
			console.setEditable(true);
			console.setEnabled(true);
			console.setAutoscrolls(true);
			
			
			cGroup = new CheckboxGroup();
			Checkbox signCb = new Checkbox("Sign", cGroup, true);
			Checkbox vsignCb = new Checkbox("Verify Signature", cGroup, false);
			Checkbox encryptCb = new Checkbox("Encrypt", cGroup, false);
			Checkbox decryptCb = new Checkbox("Decrypt", cGroup, false);
			
			
			
			signCb.setBounds(195, 10, 60, 15);
			vsignCb.setBounds(195, 25, 100, 15);
			encryptCb.setBounds(195, 40, 60, 15);
			decryptCb.setBounds(195, 55, 60, 15);
			
			
			
			progressBar.setBounds(5,140,494, 30);
			JScrollPane sp = new JScrollPane(console);
			sp.setBounds(5,154+30+2,494, 180);
			
			BufferedImage logoTitle = null;
			try {
				logoTitle = ImageIO.read(new File("./resources/logoTitle.png"));
				JLabel logoTitleLabel = new JLabel(new ImageIcon( logoTitle ));
				logoTitleLabel.setBounds(0, 0, 498, 149);
				pane.add(logoTitleLabel, BorderLayout.PAGE_START);
			} catch (IOException e) {
				String msg = "Wrong installation. The executable file must be parallel to resources/ directory. The application will try to run anyway.";
				JOptionPane.showMessageDialog(new JFrame(),msg,"Error",JOptionPane.ERROR_MESSAGE);
			}
			pane.setLayout(null);
			pane.add(selectProviderButton);
			pane.add(inputButton);
			
			pane.add(signCb);
			pane.add(vsignCb);
			pane.add(encryptCb);
			pane.add(decryptCb);
			
			pane.add(executeButton);
			pane.add(progressBar);
			pane.add(sp);
			
		}

		public void itemStateChanged(ItemEvent evt) {
			CardLayout cl = (CardLayout)(cards.getLayout());
			cl.show(cards, (String)evt.getItem());
		}

		/**
		 * Create the GUI and show it.  For thread safety,
		 * this method should be invoked from the
		 * event dispatch thread.
		 */
		private static void createAndShowGUI() {

			JFrame frame = new JFrame(Constants.APP_NAME+" - "+Constants.APP_VERSION);
		
			frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

			MainGUIDesktop gui = new MainGUIDesktop();
			gui.addComponentToPane(frame.getContentPane());

			ImageIcon icon = new ImageIcon("./resources/icon.png");
			frame.setIconImage(icon.getImage());

			frame.pack(); 
			frame.setSize(510, 400);
			frame.setResizable(false);
			frame.setVisible(true);

		}

		public static void main(String[] args) {

			try {
				UIManager.setLookAndFeel("javax.swing.plaf.metal.MetalLookAndFeel");
			} catch (UnsupportedLookAndFeelException ex) {
				ex.printStackTrace();
			} catch (IllegalAccessException ex) {
				ex.printStackTrace();
			} catch (InstantiationException ex) {
				ex.printStackTrace();
			} catch (ClassNotFoundException ex) {
				ex.printStackTrace();
			}

			UIManager.put("swing.boldMetal", Boolean.FALSE);

			javax.swing.SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					createAndShowGUI();
				}
			});
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			console.setForeground(Color.GREEN);
			if(e.getSource() == inputButton){
				int returnVal = fc.showOpenDialog(cards);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					input = file.getAbsolutePath();
					console.setText(input);
				}

			}else if(e.getSource() == executeButton){

				inputButton.setEnabled(done);
				executeButton.setEnabled(done);
				
				

				task = new Task();
				task.addPropertyChangeListener(this);
				task.execute();
			}
		}

		class Task extends SwingWorker<Void, Void> {

			@Override
			public Void doInBackground() {


				while (!done) {

					if(input!=null){

						//FileParser fp = new FileParser(Constants.DEFAUL_PWD_PATTERNS, typeProcA.isSelected());
						try {
							int numberOfRabbitsEncharmed = 0;

							//numberOfRabbitsEncharmed += fp.nogueiraSpellByPass(input, unicodeChk.isSelected());

							
							//LoggerManager.getInstance().logAtDebugTime(this.getClass().getName(), "Number of Rabbits Encharmed: "+numberOfRabbitsEncharmed+" in file "+input+" - "+fp.getPassChange());
							console.setText("Number of Rabbits Encharmed: "+numberOfRabbitsEncharmed+" in file "+input);
							//console.append("\nPasswords to lower: "+fp.getPassChange());
							//console.append("\n************************************************************************\n"+fp.getStrings());
							
							progressBar.setString("done.");		
							done = true;
							inputButton.setEnabled(done);
							executeButton.setEnabled(done);
						} catch (Exception e) {
							console.setForeground(Color.RED);
							console.setText("Magic failed: ("+e.getMessage()+")");						
							progressBar.setString("error.");
							done = true;
							inputButton.setEnabled(done);
							executeButton.setEnabled(done);
							e.printStackTrace();
						}

					}else{
						console.setForeground(Color.RED);
						console.setText("Invalid parameters.");					
						progressBar.setString("error.");
						done = true;

						inputButton.setEnabled(done);
						//outButton.setEnabled(done);
						executeButton.setEnabled(done);
					}

				}
				return null;
			}

			/*
			 * Executed in event dispatching thread
			 */
			@Override
			public void done() {
				Toolkit.getDefaultToolkit().beep();
				done = true;

				inputButton.setEnabled(done);
				executeButton.setEnabled(done);
			}
		}

		@Override
		public void propertyChange(PropertyChangeEvent arg0) {
			if (!done){
				progressBar.setString("running...");
				progressBar.setIndeterminate(true);
			} else {
				progressBar.setIndeterminate(false);
				done = false;
			}
		}
}
